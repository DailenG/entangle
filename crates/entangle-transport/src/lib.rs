//! Isolated wrapper around croc and a private, process-owned relay.
//!
//! The crate accepts relay tickets and one-time secrets, but deliberately has
//! no dependency on peer discovery or the control-link protocol.

use entangle_core::RelayTicket;
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::VecDeque,
    env,
    ffi::{OsStr, OsString},
    fmt,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
    sync::oneshot,
    time::{sleep, timeout, Instant},
};

/// Error type for locating croc, running transfers, or managing a local relay.
#[derive(Debug, Error)]
pub enum TransportError {
    /// A required filesystem or process operation failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// croc could not be located or does not meet the minimum version.
    #[error("{0}")]
    Croc(String),
    /// A croc transfer failed or timed out.
    #[error("{0}")]
    Transfer(String),
    /// The requested port was already occupied.
    #[error("relay base port {0} is already in use")]
    PortInUse(u16),
}

/// A locatable croc executable and its reported version string.
#[derive(Clone, Debug)]
pub struct Croc {
    /// Executable location.
    pub path: PathBuf,
    /// Full croc version string.
    pub version: String,
}

impl Croc {
    /// Finds croc at an explicit path, `CROC_PATH`, or the process `PATH`.
    pub fn locate(explicit: Option<PathBuf>) -> Result<Self, TransportError> {
        let candidate = explicit
            .or_else(|| env::var_os("CROC_PATH").map(PathBuf::from))
            .or_else(|| find_on_path("croc"))
            .ok_or_else(|| {
                TransportError::Croc(
                    "croc >= 10 is required; install it with `curl https://getcroc.schollz.com | bash`, `brew install croc`, or `scoop install croc`".into(),
                )
            })?;
        let output = std::process::Command::new(&candidate)
            .arg("--version")
            .output()
            .map_err(|e| {
                TransportError::Croc(format!("failed to run {}: {e}", candidate.display()))
            })?;
        if !output.status.success() {
            return Err(TransportError::Croc(format!(
                "{} --version exited with {}",
                candidate.display(),
                output.status
            )));
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let major = version
            .split_whitespace()
            .last()
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.trim_start_matches('v').parse::<u32>().ok())
            .ok_or_else(|| {
                TransportError::Croc(format!("could not parse croc version: {version}"))
            })?;
        if major < 10 {
            return Err(TransportError::Croc(format!(
                "croc >= 10 is required, found {version}; upgrade with `croc --upgrade`"
            )));
        }
        Ok(Self {
            path: candidate,
            version,
        })
    }

    /// Starts a local relay bound on all interfaces, after checking its base port.
    pub async fn start_relay(
        &self,
        base_port: u16,
        password: &str,
    ) -> Result<LocalRelay, TransportError> {
        if base_port > u16::MAX - 4 {
            return Err(TransportError::Croc(
                "relay base port must leave room for four transfer ports".into(),
            ));
        }
        LocalRelay::start(self, base_port, password).await
    }

    /// Starts a file send to a relay ticket without putting the secret in argv.
    pub async fn send(
        &self,
        file: &Path,
        secret: &Secret,
        relay: &RelayTicket,
    ) -> Result<Transfer, TransportError> {
        let mut command = base_command(self, relay, secret);
        command.args(["send", "--no-local", "--transport", "relay"]);
        command.arg(file);
        Transfer::spawn(command, true, secret.expose())
    }

    /// Starts a receive into `out_dir`, retrying fast startup failures up to twice.
    pub async fn receive(
        &self,
        out_dir: &Path,
        secret: &Secret,
        relay: &RelayTicket,
    ) -> Result<Transfer, TransportError> {
        std::fs::create_dir_all(out_dir)?;
        let mut command = base_command(self, relay, secret);
        command.args(["--out", &out_dir.to_string_lossy()]);
        Transfer::spawn_with_retry(command, false, 2, secret.expose())
    }
}

fn base_command(croc: &Croc, relay: &RelayTicket, secret: &Secret) -> Command {
    let mut command = Command::new(&croc.path);
    command
        .arg("--relay")
        .arg(relay_address(&relay.host, relay.port))
        .arg("--pass")
        .arg(&relay.password)
        .args([
            "--yes",
            "--overwrite",
            "--disable-clipboard",
            "--ignore-stdin",
        ])
        // Croc v10+ accepts the invitation through this environment variable, not argv.
        .env("CROC_SECRET", secret.expose())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
        .find(|path| path.is_file())
}

fn relay_address(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// An opaque, one-time croc transfer secret.
#[derive(Clone, Eq, PartialEq)]
pub struct Secret(String);

impl Secret {
    /// Generates a 4-digit prefix and 128 random bits in lowercase hex.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let pin = OsRng.next_u32() % 10_000;
        Self(format!("{pin:04}-{}", hex::encode(bytes)))
    }

    /// Exposes the secret for the croc child environment.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Wraps a secret received over a link without formatting it into logs.
    pub fn from_string(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(****)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("****")
    }
}

/// A child croc relay that is killed on drop and can be shut down explicitly.
pub struct LocalRelay {
    child: Child,
    base_port: u16,
    password: String,
}

impl LocalRelay {
    /// Starts a five-port local relay, requiring the first port to be free.
    pub async fn start(
        croc: &Croc,
        base_port: u16,
        password: &str,
    ) -> Result<Self, TransportError> {
        if base_port > u16::MAX - 4 {
            return Err(TransportError::Croc(
                "relay base port must leave room for four transfer ports".into(),
            ));
        }
        let listener = TcpListener::bind(("0.0.0.0", base_port))
            .map_err(|_| TransportError::PortInUse(base_port))?;
        drop(listener);
        let ports = (base_port..=base_port.saturating_add(4))
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut child = Command::new(&croc.path)
            .arg("--pass")
            .arg(password)
            .args(["relay", "--host", "0.0.0.0", "--ports"])
            .arg(ports)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpListener::bind(("0.0.0.0", base_port)).is_err()
                && tokio::net::TcpStream::connect(("127.0.0.1", base_port))
                    .await
                    .is_ok()
            {
                return Ok(Self {
                    child,
                    base_port,
                    password: password.to_owned(),
                });
            }
            if Instant::now() >= deadline {
                let _ = child.kill().await;
                return Err(TransportError::Transfer(format!(
                    "local croc relay did not become ready on port {base_port} within 5 seconds"
                )));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Creates a peer-visible relay ticket for the chosen interface address.
    pub fn ticket(&self, advertised_host: impl Into<String>) -> RelayTicket {
        RelayTicket {
            host: advertised_host.into(),
            port: self.base_port,
            password: self.password.clone(),
        }
    }

    /// Stops the relay process and waits for it to exit.
    pub async fn shutdown(mut self) -> Result<(), TransportError> {
        self.child.kill().await?;
        let _ = self.child.wait().await?;
        Ok(())
    }
}

/// Result from a completed croc transfer.
#[derive(Clone, Debug)]
pub struct TransferOutcome {
    /// Whether the child process exited successfully.
    pub success: bool,
    /// Recent process output, bounded to approximately four KiB.
    pub output_tail: String,
}

/// A running croc child process.
pub struct Transfer {
    child: Child,
    tail: Arc<Mutex<VecDeque<u8>>>,
    ready: Option<oneshot::Receiver<()>>,
    retry_command: Option<CommandSpec>,
    retries: u8,
    started_at: Instant,
    secret: String,
}

impl Transfer {
    fn spawn(command: Command, sending: bool, secret: &str) -> Result<Self, TransportError> {
        Self::spawn_with_retry(command, sending, 0, secret)
    }

    fn spawn_with_retry(
        mut command: Command,
        sending: bool,
        retries: u8,
        secret: &str,
    ) -> Result<Self, TransportError> {
        let retry_command = if retries > 0 {
            Some(CommandSpec::from_command(&command))
        } else {
            None
        };
        let child = command.spawn()?;
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(4096)));
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut transfer = Self {
            child,
            tail: Arc::clone(&tail),
            ready: sending.then_some(ready_rx),
            retry_command,
            retries,
            started_at: Instant::now(),
            secret: secret.to_owned(),
        };
        if let Some(stdout) = transfer.child.stdout.take() {
            tokio::spawn(drain_output(stdout, Arc::clone(&tail), Some(ready_tx)));
        } else {
            let _ = ready_tx.send(());
        }
        if let Some(stderr) = transfer.child.stderr.take() {
            tokio::spawn(drain_output(stderr, tail, None));
        }
        if sending {
            if let Some(ready) = transfer.ready.take() {
                let (tx, rx) = oneshot::channel();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = ready => {},
                        _ = sleep(Duration::from_millis(700)) => {},
                    }
                    let _ = tx.send(());
                });
                transfer.ready = Some(rx);
            }
        }
        Ok(transfer)
    }

    /// Resolves when croc indicates readiness, with a short fallback delay.
    pub async fn ready(&mut self) {
        if let Some(ready) = self.ready.take() {
            let _ = ready.await;
        }
    }

    /// Waits for exit, enforcing a deadline and retrying receive startup failures.
    pub async fn wait(mut self, duration: Duration) -> Result<TransferOutcome, TransportError> {
        let deadline = Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let result = timeout(remaining, self.child.wait()).await;
            match result {
                Err(_) => {
                    let _ = self.child.kill().await;
                    return Err(TransportError::Transfer(format!(
                        "croc transfer timed out; {}",
                        self.tail_text()
                    )));
                }
                Ok(Err(error)) => return Err(error.into()),
                Ok(Ok(status)) if status.success() => {
                    return Ok(TransferOutcome {
                        success: true,
                        output_tail: self.tail_text(),
                    })
                }
                Ok(Ok(_))
                    if self.retries > 0
                        && self.started_at.elapsed() < Duration::from_secs(3)
                        && Instant::now() < deadline =>
                {
                    let spec = self.retry_command.clone().expect("retry command captured");
                    let remaining_retries = self.retries - 1;
                    sleep(Duration::from_millis(
                        200 * u64::from(3 - remaining_retries),
                    ))
                    .await;
                    let secret = self.secret.clone();
                    self =
                        Self::spawn_with_retry(spec.command(), false, remaining_retries, &secret)?;
                }
                Ok(Ok(status)) => {
                    return Err(TransportError::Transfer(format!(
                        "croc exited with {status}; {}",
                        self.tail_text()
                    )))
                }
            }
        }
    }

    /// Terminates this transfer.
    pub async fn abort(mut self) -> Result<(), TransportError> {
        self.child.kill().await?;
        let _ = self.child.wait().await?;
        Ok(())
    }

    fn tail_text(&self) -> String {
        let bytes: Vec<_> = self.tail.lock().unwrap().iter().copied().collect();
        String::from_utf8_lossy(&bytes)
            .replace(&self.secret, "[REDACTED]")
            .trim()
            .to_owned()
    }
}

#[derive(Clone)]
struct CommandSpec {
    program: OsString,
    args: Vec<OsString>,
    envs: Vec<(OsString, Option<OsString>)>,
}

impl CommandSpec {
    fn from_command(command: &Command) -> Self {
        let std_command = command.as_std();
        Self {
            program: std_command.get_program().to_owned(),
            args: std_command.get_args().map(OsStr::to_owned).collect(),
            envs: std_command
                .get_envs()
                .map(|(key, value)| (key.to_owned(), value.map(OsStr::to_owned)))
                .collect(),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        for (key, value) in &self.envs {
            if let Some(value) = value {
                command.env(key, value);
            } else {
                command.env_remove(key);
            }
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
}

async fn drain_output<R: AsyncRead + Unpin>(
    stream: R,
    tail: Arc<Mutex<VecDeque<u8>>>,
    ready: Option<oneshot::Sender<()>>,
) {
    let mut lines = BufReader::new(stream).lines();
    let mut ready = ready;
    while let Ok(Some(line)) = lines.next_line().await {
        append_tail(&tail, line.as_bytes());
        append_tail(&tail, b"\n");
        if ready.is_some()
            && ["Code is", "Sending", "Waiting", "Ready"]
                .iter()
                .any(|needle| line.contains(needle))
        {
            if let Some(tx) = ready.take() {
                let _ = tx.send(());
            }
        }
    }
}

fn append_tail(tail: &Mutex<VecDeque<u8>>, data: &[u8]) {
    let mut tail = tail.lock().unwrap();
    for byte in data {
        if tail.len() == 4096 {
            tail.pop_front();
        }
        tail.push_back(*byte);
    }
}

/// Parses an IPv4 or IPv6 relay socket endpoint.
pub fn relay_socket(host: &str, port: u16) -> Result<SocketAddr, TransportError> {
    relay_address(host, port)
        .parse()
        .map_err(|error| TransportError::Croc(format!("invalid relay address: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_formatted_unique_and_redacted() {
        let first = Secret::generate();
        let generated: std::collections::HashSet<_> = (0..100)
            .map(|_| Secret::generate().expose().to_owned())
            .collect();
        assert_eq!(generated.len(), 100);
        assert_eq!(first.expose().len(), 37);
        assert!(first.expose().as_bytes()[..4]
            .iter()
            .all(u8::is_ascii_digit));
        assert_eq!(first.expose().as_bytes()[4], b'-');
        assert_eq!(format!("{first:?}"), "Secret(****)");
        assert_eq!(format!("{first}"), "****");
        assert!(!format!("{first:?}").contains(first.expose()));
    }

    #[test]
    fn relay_ticket_endpoint_accepts_ipv4() {
        assert_eq!(relay_socket("127.0.0.1", 9109).unwrap().port(), 9109);
    }

    #[test]
    fn relay_endpoint_brackets_ipv6() {
        assert_eq!(relay_socket("::1", 9109).unwrap().to_string(), "[::1]:9109");
    }
}

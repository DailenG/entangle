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
    fmt, fs, io,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, Signal, System};
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
    /// All attempted relay port ranges were occupied.
    #[error("relay base port range {start}..={end} (step 5) is already in use")]
    PortRangesInUse { start: u16, end: u16 },
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
    /// Finds croc at an explicit path, `CROC_PATH`, beside the current executable, or on `PATH`.
    pub fn locate(explicit: Option<PathBuf>) -> Result<Self, TransportError> {
        let candidate = explicit
            .or_else(|| env::var_os("CROC_PATH").map(PathBuf::from))
            .or_else(|| env::current_exe().ok().and_then(|exe| sibling_croc(&exe)))
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
        let mut last_port = base_port;
        for offset in 0..=8_u16 {
            let Some(port) = base_port.checked_add(offset * 5) else {
                break;
            };
            if port > u16::MAX - 4 {
                break;
            }
            last_port = port;
            match LocalRelay::start(self, port, password).await {
                Ok(relay) => {
                    if port != base_port {
                        tracing::warn!(
                            configured_port = base_port,
                            selected_port = port,
                            "configured relay range is occupied; firewall rules for the configured range will not cover the selected relay range"
                        );
                    }
                    return Ok(relay);
                }
                Err(TransportError::PortInUse(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Err(TransportError::PortRangesInUse {
            start: base_port,
            end: last_port,
        })
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

/// `kill_on_drop` does not run when Entangle is terminated without dropping its
/// runtime, such as during an MCP client's reload.
fn spawn_croc(mut command: Command) -> io::Result<Child> {
    install_parent_death_signal(&mut command);
    let child = command.spawn()?;
    #[cfg(windows)]
    assign_to_job(&child);
    Ok(child)
}

#[cfg(target_os = "linux")]
/// PDEATHSIG fires when the spawning thread exits. Croc spawns run on Tokio
/// worker threads that live for the runtime; the `getppid` check closes the
/// race where Entangle exits before the child arms the signal.
fn install_parent_death_signal(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    let parent_pid = std::process::id() as libc::pid_t;
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                libc::_exit(1);
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn install_parent_death_signal(_: &mut Command) {}

#[cfg(windows)]
/// Keeps the process-wide handle open so OS closure at process exit triggers
/// KILL_ON_JOB_CLOSE for every assigned croc child.
struct JobHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for JobHandle {}

#[cfg(windows)]
unsafe impl Sync for JobHandle {}

#[cfg(windows)]
/// Assigns croc children to the process-wide kill-on-close job.
fn assign_to_job(child: &Child) {
    use std::{mem::size_of, sync::OnceLock};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    };

    static JOB: OnceLock<Option<JobHandle>> = OnceLock::new();
    let job = JOB.get_or_init(|| unsafe {
        let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if handle.is_null() {
            tracing::warn!("could not create the croc child-process job object");
            return None;
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            handle,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
        {
            tracing::warn!("could not configure the croc child-process job object");
            return None;
        }
        Some(JobHandle(handle))
    });

    if let Some(job) = job {
        let Some(raw_handle) = child.raw_handle() else {
            return;
        };
        let assigned = unsafe { AssignProcessToJobObject(job.0, raw_handle as HANDLE) };
        if assigned == 0 {
            tracing::warn!("could not assign a croc child process to the job object");
        }
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
        .find(|path| path.is_file())
}

fn sibling_croc(exe: &Path) -> Option<PathBuf> {
    let candidate = exe
        .parent()?
        .join(format!("croc{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
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
    pid: u32,
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
        let listener = TcpListener::bind(("0.0.0.0", base_port)).map_err(|error| {
            if error.kind() == io::ErrorKind::AddrInUse {
                TransportError::PortInUse(base_port)
            } else {
                TransportError::Io(error)
            }
        })?;
        drop(listener);
        let ports = (base_port..=base_port.saturating_add(4))
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut command = Command::new(&croc.path);
        command
            .arg("--pass")
            .arg(password)
            .args(["relay", "--host", "0.0.0.0", "--ports"])
            .arg(ports)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = spawn_croc(command)?;
        let pid = child.id().expect("spawned relay child must have a pid");
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
                    pid,
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

    /// Returns the relay process ID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Stops the relay process and waits for it to exit.
    pub async fn shutdown(mut self) -> Result<(), TransportError> {
        self.child.kill().await?;
        let _ = self.child.wait().await?;
        Ok(())
    }
}

/// Reclaims a previously recorded relay only when its PID still runs the same executable.
pub fn reap_stale_relay(record: &Path) {
    let Ok(contents) = fs::read_to_string(record) else {
        return;
    };
    let mut lines = contents.lines();
    let Some(pid) = lines.next().and_then(|line| line.parse::<u32>().ok()) else {
        return;
    };
    let Some(executable) = lines.next().map(Path::new) else {
        return;
    };
    if pid == 0 || !executable.is_absolute() {
        return;
    }

    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let Some(process) = system.process(pid) else {
        let _ = fs::remove_file(record);
        return;
    };
    let Some(actual_executable) = process.exe() else {
        let _ = fs::remove_file(record);
        return;
    };
    if !executable_paths_match(actual_executable, executable) {
        let _ = fs::remove_file(record);
        return;
    }
    if !process.kill_with(Signal::Kill).unwrap_or(false) {
        tracing::warn!(
            relay_pid = pid.as_u32(),
            "could not terminate stale croc relay"
        );
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        match system.process(pid) {
            None => break,
            Some(process) if process.status() == ProcessStatus::Zombie => break,
            Some(_) if std::time::Instant::now() >= deadline => break,
            Some(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let _ = fs::remove_file(record);
}

fn executable_paths_match(actual: &Path, recorded: &Path) -> bool {
    if !actual.is_absolute() || !recorded.is_absolute() {
        return false;
    }
    let actual = fs::canonicalize(actual).unwrap_or_else(|_| actual.to_path_buf());
    let recorded = fs::canonicalize(recorded).unwrap_or_else(|_| recorded.to_path_buf());
    #[cfg(windows)]
    {
        actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&recorded.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        actual == recorded
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
        command: Command,
        sending: bool,
        retries: u8,
        secret: &str,
    ) -> Result<Self, TransportError> {
        let retry_command = if retries > 0 {
            Some(CommandSpec::from_command(&command))
        } else {
            None
        };
        let child = spawn_croc(command)?;
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

    fn croc_for_test() -> Option<Croc> {
        match Croc::locate(None) {
            Ok(croc) => Some(croc),
            Err(error) if std::env::var("ENTANGLE_REQUIRE_CROC").as_deref() != Ok("1") => {
                eprintln!("skipping croc-dependent transport test: {error}");
                None
            }
            Err(error) => panic!("ENTANGLE_REQUIRE_CROC=1 but croc is unavailable: {error}"),
        }
    }

    fn free_relay_base_port() -> u16 {
        for _ in 0..100 {
            let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            if port <= u16::MAX - 4
                && (0..=4).all(|offset| TcpListener::bind(("0.0.0.0", port + offset)).is_ok())
            {
                return port;
            }
        }
        panic!("could not find an available relay port range");
    }

    fn wait_for_relay(port: u16) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn wait_for_child_exit(child: &mut std::process::Child) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    struct TestChild(std::process::Child);

    impl Drop for TestChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    #[test]
    fn stale_relay_is_reaped_only_when_its_executable_matches() {
        let Some(croc) = croc_for_test() else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let base_port = free_relay_base_port();
        let ports = (base_port..=base_port + 4)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut child = TestChild(
            std::process::Command::new(&croc.path)
                .arg("--pass")
                .arg("orphan-test-password")
                .args(["relay", "--host", "0.0.0.0", "--ports"])
                .arg(ports)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(wait_for_relay(base_port), "croc relay did not start");

        let record = temp.path().join("relay.pid");
        let executable = fs::canonicalize(&croc.path).unwrap();
        fs::write(
            &record,
            format!("{}\n{}\n", child.0.id(), executable.display()),
        )
        .unwrap();
        reap_stale_relay(&record);

        assert!(wait_for_child_exit(&mut child.0), "croc relay did not exit");
        assert!(!record.exists());
        assert!(TcpListener::bind(("0.0.0.0", base_port)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn stale_record_does_not_kill_a_different_executable() {
        let temp = tempfile::tempdir().unwrap();
        let mut child = TestChild(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let record = temp.path().join("relay.pid");
        let unrelated_executable = std::env::current_exe().unwrap();
        fs::write(
            &record,
            format!("{}\n{}\n", child.0.id(), unrelated_executable.display()),
        )
        .unwrap();

        reap_stale_relay(&record);

        assert!(child.0.try_wait().unwrap().is_none());
        assert!(!record.exists());
        child.0.kill().unwrap();
        let _ = child.0.wait().unwrap();
    }

    #[test]
    fn missing_and_garbage_relay_records_are_noops() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing-relay.pid");
        reap_stale_relay(&missing);
        assert!(!missing.exists());

        let garbage = temp.path().join("garbage-relay.pid");
        fs::write(&garbage, "not a relay record").unwrap();
        reap_stale_relay(&garbage);
        assert_eq!(fs::read_to_string(garbage).unwrap(), "not a relay record");
    }

    #[test]
    fn sibling_croc_finds_existing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir
            .path()
            .join(format!("entangle{}", std::env::consts::EXE_SUFFIX));
        let croc = dir
            .path()
            .join(format!("croc{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&croc, []).unwrap();

        assert_eq!(sibling_croc(&exe), Some(croc));
    }

    #[test]
    fn sibling_croc_returns_none_when_binary_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir
            .path()
            .join(format!("entangle{}", std::env::consts::EXE_SUFFIX));

        assert_eq!(sibling_croc(&exe), None);
    }

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

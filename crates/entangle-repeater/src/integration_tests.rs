use crate::{
    client::{self, RepeaterClient},
    server::{self, ServerConfig},
    store::Store,
    wire::{Frame, CLOSE, OPEN, OPEN_FAIL},
};
use entangle_transport::{self, LinkKeys};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Barrier,
    task::JoinHandle,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

struct TestServer {
    _root: tempfile::TempDir,
    root_path: std::path::PathBuf,
    url: String,
    public: [u8; 32],
    handle: JoinHandle<Result<(), server::ServerError>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn test_root_path(path: &Path) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        path.canonicalize().unwrap()
    }
    #[cfg(not(target_os = "macos"))]
    {
        path.to_path_buf()
    }
}

async fn start_server() -> TestServer {
    start_server_with_options(Duration::from_secs(10), true).await
}

async fn start_server_with_timeout(handshake_timeout: Duration) -> TestServer {
    start_server_with_options(handshake_timeout, true).await
}

async fn start_server_with_options(handshake_timeout: Duration, requests: bool) -> TestServer {
    let root = tempfile::tempdir().unwrap();
    let root_path = test_root_path(root.path());
    let store = Store::new(&root_path);
    let private = store.key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(server::serve_on_listener_with_timeout(
        listener,
        ServerConfig {
            listen: addr,
            path: "/entangle".into(),
            root: root_path.clone(),
            requests,
        },
        handshake_timeout,
    ));
    tokio::time::sleep(Duration::from_millis(30)).await;
    TestServer {
        _root: root,
        root_path,
        url: format!("ws://{addr}/entangle"),
        public: entangle_transport::public_key(&private),
        handle,
    }
}

#[tokio::test]
async fn partial_http_request_is_closed_by_handshake_deadline() {
    let server = start_server_with_timeout(Duration::from_millis(50)).await;
    let address = server
        .url
        .strip_prefix("ws://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"GET /entangle").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("partial HTTP request should time out")
        .unwrap();
    assert!(response.is_empty());
}

async fn enroll(server: &TestServer, key: [u8; 32], secret: [u8; 32]) {
    let url = server.url.clone();
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let store = server_store(server);
    store.add_invite(secret, expiry, None).unwrap();
    client::enroll(&url, key, server.public, secret, None)
        .await
        .unwrap();
}

async fn rejected_without_msg2(
    server: &TestServer,
    private: [u8; 32],
    payload: serde_json::Value,
) -> bool {
    let (mut ws, _) = connect_async(&server.url).await.unwrap();
    let params = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let mut noise = snow::Builder::new(params)
        .local_private_key(&private)
        .unwrap()
        .remote_public_key(&server.public)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut first = vec![0; u16::MAX as usize];
    let size = noise
        .write_message(&serde_json::to_vec(&payload).unwrap(), &mut first)
        .unwrap();
    ws.send(Message::Binary(first[..size].to_vec()))
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
        Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => true,
        Ok(Some(Ok(_))) | Err(_) => false,
    }
}

fn server_store(server: &TestServer) -> Store {
    Store::new(&server.root_path)
}

async fn open_sessions(
    server: &TestServer,
    a_private: [u8; 32],
    a_group: &str,
    b_private: [u8; 32],
    b_group: &str,
) -> (RepeaterClient, RepeaterClient) {
    let a = client::connect(&server.url, a_private, server.public, a_group)
        .await
        .unwrap();
    let b = client::connect(&server.url, b_private, server.public, b_group)
        .await
        .unwrap();
    (a, b)
}

#[tokio::test]
async fn split_dialer_lists_peers_and_reports_incoming_sources() {
    let server = start_server().await;
    let a_private = entangle_transport::generate_static();
    let b_private = entangle_transport::generate_static();
    enroll(&server, a_private, [21; 32]).await;
    enroll(&server, b_private, [22; 32]).await;
    let (a, b) = open_sessions(&server, a_private, "aaaaaaaa", b_private, "aaaaaaaa").await;
    let a_key = a.static_public;
    let b_key = b.static_public;
    let (a_dialer, _a_incoming) = a.split();
    let (_b_dialer, mut b_incoming) = b.split();

    let directory = a_dialer.list().await.unwrap();
    assert_eq!(directory.len(), 1);
    assert_eq!(directory[0].key, b_key);
    let _opened = a_dialer.open(b_key).await.unwrap();
    let incoming = b_incoming.accept().await.unwrap();
    assert_eq!(incoming.source, a_key);
}

#[tokio::test]
async fn incoming_burst_does_not_block_list_or_close_the_session() {
    let server = start_server().await;
    let a_private = entangle_transport::generate_static();
    let b_private = entangle_transport::generate_static();
    enroll(&server, a_private, [41; 32]).await;
    enroll(&server, b_private, [42; 32]).await;
    let (a, b) = open_sessions(&server, a_private, "aaaaaaaa", b_private, "aaaaaaaa").await;
    let b_public = b.static_public;
    let (a_dialer, _a_incoming) = a.split();
    let (b_dialer, b_incoming) = b.split();

    let mut streams = Vec::new();
    for _ in 0..40 {
        streams.push(a_dialer.open(b_public).await.unwrap());
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while b_incoming.queued() < 32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("incoming queue should fill without blocking the reader");

    let directory = tokio::time::timeout(Duration::from_secs(2), b_dialer.list())
        .await
        .expect("LIST must not wait for incoming-stream acceptance")
        .unwrap();
    assert_eq!(directory.len(), 1);
    assert!(!a_dialer.is_closed());
    assert!(!b_dialer.is_closed());
    drop(streams);
}

#[tokio::test]
async fn sessions_route_large_streams_and_isolate_groups() {
    let server = start_server().await;
    let a_private = entangle_transport::generate_static();
    let b_private = entangle_transport::generate_static();
    let c_private = entangle_transport::generate_static();
    enroll(&server, a_private, [11; 32]).await;
    enroll(&server, b_private, [12; 32]).await;
    enroll(&server, c_private, [13; 32]).await;

    let (mut a, mut b) = open_sessions(&server, a_private, "aaaaaaaa", b_private, "aaaaaaaa").await;
    assert_eq!(a.list().await.unwrap().len(), 1);
    assert_eq!(b.list().await.unwrap().len(), 1);

    let a_stream = a.open(b.static_public).await.unwrap();
    let b_stream = b.accept().await.unwrap();
    let payload = (0..200 * 1024).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let (a_read, a_write) = tokio::io::split(a_stream.into_io());
    let (b_read, b_write) = tokio::io::split(b_stream.into_io());
    let mut a_read = a_read;
    let mut b_read = b_read;
    let mut a_write = a_write;
    let mut b_write = b_write;
    let sent = payload.clone();
    let send_a = tokio::spawn(async move {
        a_write.write_all(&sent).await.unwrap();
        a_write
    });
    let mut received = vec![0; payload.len()];
    b_read.read_exact(&mut received).await.unwrap();
    let mut a_write = send_a.await.unwrap();
    assert_eq!(Sha256::digest(&received), Sha256::digest(&payload));

    let reverse = payload.iter().rev().copied().collect::<Vec<_>>();
    let sent = reverse.clone();
    let send_b = tokio::spawn(async move { b_write.write_all(&sent).await.unwrap() });
    let mut received_reverse = vec![0; reverse.len()];
    a_read.read_exact(&mut received_reverse).await.unwrap();
    send_b.await.unwrap();
    assert_eq!(Sha256::digest(&received_reverse), Sha256::digest(&reverse));

    a_write.shutdown().await.unwrap();
    let mut eof = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), b_read.read(&mut eof))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    let mut c = client::connect(&server.url, c_private, server.public, "bbbbbbbb")
        .await
        .unwrap();
    assert!(c.list().await.unwrap().is_empty());
    c.send_frame(Frame {
        kind: OPEN,
        stream: 1,
        body: a.static_public.to_vec(),
    })
    .await
    .unwrap();
    let failed = c.recv_frame().await.unwrap();
    assert_eq!(failed.kind, OPEN_FAIL);
    assert_eq!(failed.stream, 1);
}

#[tokio::test]
async fn stream_half_close_allows_a_reply_after_request_eof() {
    let server = start_server().await;
    let a_private = entangle_transport::generate_static();
    let b_private = entangle_transport::generate_static();
    enroll(&server, a_private, [31; 32]).await;
    enroll(&server, b_private, [32; 32]).await;
    let (a, b) = open_sessions(&server, a_private, "aaaaaaaa", b_private, "aaaaaaaa").await;
    let b_public = b.static_public;
    let (a_dialer, _) = a.split();
    let (_b_dialer, mut b_incoming) = b.split();
    let a_stream = a_dialer.open(b_public).await.unwrap();
    let b_stream = b_incoming.accept().await.unwrap();
    let (mut a_reader, mut a_writer) = tokio::io::split(a_stream.into_io());
    let (mut b_reader, mut b_writer) = tokio::io::split(b_stream.stream.into_io());

    tokio::time::timeout(Duration::from_secs(5), async {
        let request = b"request before half-close";
        a_writer.write_all(request).await.unwrap();
        a_writer.shutdown().await.unwrap();

        let mut received_request = Vec::new();
        b_reader.read_to_end(&mut received_request).await.unwrap();
        assert_eq!(received_request, request);

        let reply = b"reply after request EOF";
        b_writer.write_all(reply).await.unwrap();
        b_writer.shutdown().await.unwrap();

        let mut received_reply = Vec::new();
        a_reader.read_to_end(&mut received_reply).await.unwrap();
        assert_eq!(received_reply, reply);
    })
    .await
    .expect("both directions should remain usable after a half-close");
}

async fn exchange_payload(
    stream: entangle_transport::BoxedIo,
    payload: Vec<u8>,
    completed: Arc<Barrier>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let expected: [u8; 32] = Sha256::digest(&payload).into();
    let size = payload.len();
    let (send_result, received) = tokio::join!(writer.write_all(&payload), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut received = vec![0; size];
        reader.read_exact(&mut received).await.unwrap();
        received
    });
    send_result.unwrap();
    assert_eq!(Sha256::digest(received).as_slice(), expected);
    completed.wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_bidirectional_transfers_on_two_streams_finish_without_deadlock() {
    const SIZE: usize = 8 * 1024 * 1024;

    let server = start_server().await;
    let a_private = entangle_transport::generate_static();
    let b_private = entangle_transport::generate_static();
    enroll(&server, a_private, [41; 32]).await;
    enroll(&server, b_private, [42; 32]).await;
    let (mut a, mut b) = open_sessions(&server, a_private, "aaaaaaaa", b_private, "aaaaaaaa").await;

    let a_to_b = a.open(b.static_public).await.unwrap();
    let b_to_a = b.open(a.static_public).await.unwrap();
    let b_incoming = b.accept().await.unwrap();
    let a_incoming = a.accept().await.unwrap();

    let payload_a_to_b = (0..SIZE)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let payload_b_to_a = (0..SIZE)
        .map(|index| ((index * 7 + 19) % 251) as u8)
        .collect::<Vec<_>>();
    let completed = Arc::new(Barrier::new(4));
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            exchange_payload(
                a_to_b.into_io(),
                payload_a_to_b.clone(),
                Arc::clone(&completed),
            ),
            exchange_payload(b_incoming.into_io(), payload_a_to_b, Arc::clone(&completed),),
            exchange_payload(
                b_to_a.into_io(),
                payload_b_to_a.clone(),
                Arc::clone(&completed),
            ),
            exchange_payload(a_incoming.into_io(), payload_b_to_a, Arc::clone(&completed),),
        )
    })
    .await;
    assert!(
        result.is_ok(),
        "two-stream bidirectional transfer exceeded 30 seconds"
    );
}

#[tokio::test]
async fn enrollment_rejects_unenrolled_reused_and_expired_credentials_and_revokes_live_sessions() {
    let server = start_server().await;
    let enrolled = entangle_transport::generate_static();
    let secret = [21; 32];
    enroll(&server, enrolled, secret).await;

    assert!(
        rejected_without_msg2(
            &server,
            enrolled,
            json!({"v": 1, "mode": "enroll", "invite": hex::encode(secret)})
        )
        .await
    );

    let store = server_store(&server);
    let expired_secret = [22; 32];
    store
        .add_invite(
            expired_secret,
            (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
            None,
        )
        .unwrap();
    let expired_key = entangle_transport::generate_static();
    assert!(
        rejected_without_msg2(
            &server,
            expired_key,
            json!({"v": 1, "mode": "enroll", "invite": hex::encode(expired_secret)})
        )
        .await
    );

    let unapproved = entangle_transport::generate_static();
    assert!(
        rejected_without_msg2(
            &server,
            unapproved,
            json!({"v": 1, "mode": "session", "group": "aaaaaaaa"})
        )
        .await
    );

    let mut live = client::connect(&server.url, enrolled, server.public, "aaaaaaaa")
        .await
        .unwrap();
    let mut devices = store.devices().unwrap();
    devices
        .devices
        .get_mut(&hex::encode(entangle_transport::public_key(&enrolled)))
        .unwrap()
        .revoked = true;
    store.save_devices(&devices).unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(3), live.recv_frame())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.kind, CLOSE);
}

#[tokio::test]
async fn plain_http_requests_get_empty_404_responses() {
    let server = start_server().await;
    let requests: [&[u8]; 3] = [
        b"GET /entangle HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"GET /not-entangle HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        b"GET /entangle HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: invalid\r\nSec-WebSocket-Version: 13\r\n\r\n",
    ];
    for request in requests {
        let addr: SocketAddr = server.url["ws://".len()..]
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 404"), "{text:?}");
        assert!(text.ends_with("\r\n\r\n"), "{text:?}");
    }
}

#[tokio::test]
async fn forwarding_does_not_expose_end_to_end_noise_plaintext() {
    let server = start_server().await;
    let a_private = entangle_transport::generate_static();
    let b_private = entangle_transport::generate_static();
    enroll(&server, a_private, [31; 32]).await;
    enroll(&server, b_private, [32; 32]).await;
    let (mut a, mut b) = open_sessions(&server, a_private, "aaaaaaaa", b_private, "aaaaaaaa").await;
    let a_stream = a.open(b.static_public).await.unwrap();
    let b_stream = b.accept().await.unwrap();
    let keys_a = LinkKeys {
        static_private: entangle_transport::generate_static(),
        psk: [47; 32],
    };
    let keys_b = LinkKeys {
        static_private: entangle_transport::generate_static(),
        psk: [47; 32],
    };
    let (secure_a, secure_b) = tokio::join!(
        entangle_transport::connect_io(a_stream.into_io(), &keys_a, Duration::from_secs(3)),
        entangle_transport::accept_io(b_stream.into_io(), &keys_b, Duration::from_secs(3))
    );
    let mut secure_a = secure_a.unwrap();
    let mut secure_b = secure_b.unwrap();
    let marker = [0xA7; 32];
    server::clear_forwarded_data();
    secure_a.send(&marker).await.unwrap();
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(2),
            secure_b.recv(Duration::from_secs(2))
        )
        .await
        .unwrap()
        .unwrap(),
        marker
    );
    let forwarded = server::forwarded_data();
    assert!(!forwarded
        .windows(marker.len())
        .any(|window| window == marker));
}

async fn request_once(
    server: &TestServer,
    private: [u8; 32],
    label: Option<&str>,
) -> (
    tokio::task::JoinHandle<Result<client::RequestOutcome, client::ClientError>>,
    tokio::sync::oneshot::Receiver<([u8; 32], entangle_core::sas::Sas)>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let url = server.url.clone();
    let label = label.map(str::to_owned);
    let handle = tokio::spawn(async move {
        let result = client::request(&url, private, label.as_deref(), move |public, sas| {
            let _ = tx.send((public, sas));
        })
        .await;
        result
    });
    (handle, rx)
}

async fn wait_for_request(server: &TestServer) -> crate::store::EnrollmentRequest {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(request) = server_store(server).requests().unwrap().into_iter().next() {
                return request;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn request_approve_matches_sas_and_connects() {
    let server = start_server().await;
    let private = entangle_transport::generate_static();
    let (handle, sas_rx) = request_once(&server, private, Some("alice")).await;
    let (_, sas) = sas_rx.await.unwrap();
    let request = wait_for_request(&server).await;
    assert_eq!(request.sas, sas);
    let key = entangle_transport::public_key(&private);
    server_store(&server)
        .decide_device(key, request.label, true)
        .unwrap();
    let outcome = handle.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        client::RequestOutcome::Approved {
            repeater_public: server.public
        }
    );
    assert!(server_store(&server).device_allowed(&key).unwrap());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _client = client::connect(&server.url, private, server.public, "aaaaaaaa")
        .await
        .unwrap();
}

#[tokio::test]
async fn request_deny_rejects_session() {
    let server = start_server().await;
    let private = entangle_transport::generate_static();
    let (handle, _sas_rx) = request_once(&server, private, None).await;
    let request = wait_for_request(&server).await;
    server_store(&server)
        .decide_device(
            entangle_transport::public_key(&private),
            request.label,
            false,
        )
        .unwrap();
    assert_eq!(
        handle.await.unwrap().unwrap(),
        client::RequestOutcome::Denied
    );
    assert!(
        client::connect(&server.url, private, server.public, "aaaaaaaa")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn disconnected_request_is_removed() {
    let server = start_server().await;
    let private = entangle_transport::generate_static();
    let (handle, _sas_rx) = request_once(&server, private, None).await;
    let _ = wait_for_request(&server).await;
    handle.abort();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if server_store(&server).requests().unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn second_request_from_same_ip_is_busy() {
    let server = start_server().await;
    let first_private = entangle_transport::generate_static();
    let second_private = entangle_transport::generate_static();
    let (first, _sas_rx) = request_once(&server, first_private, None).await;
    let _ = wait_for_request(&server).await;
    let second = client::request(&server.url, second_private, None, |_public, _sas| {}).await;
    assert!(matches!(second, Err(client::ClientError::Busy)));
    first.abort();
}

#[tokio::test]
async fn disabled_requests_keep_invites_working() {
    let server = start_server_with_options(Duration::from_secs(10), false).await;
    let private = entangle_transport::generate_static();
    assert!(
        client::request(&server.url, private, None, |_public, _sas| {})
            .await
            .is_err()
    );
    enroll(&server, private, [99; 32]).await;
    let _client = client::connect(&server.url, private, server.public, "aaaaaaaa")
        .await
        .unwrap();
}

#[tokio::test]
async fn revoked_request_can_be_approved_again() {
    let server = start_server().await;
    let private = entangle_transport::generate_static();
    let key = entangle_transport::public_key(&private);
    server_store(&server)
        .decide_device(key, Some("old".into()), false)
        .unwrap();
    let (handle, _sas_rx) = request_once(&server, private, Some("new")).await;
    let request = wait_for_request(&server).await;
    server_store(&server)
        .decide_device(key, request.label, true)
        .unwrap();
    assert!(matches!(
        handle.await.unwrap().unwrap(),
        client::RequestOutcome::Approved { .. }
    ));
    assert!(server_store(&server).device_allowed(&key).unwrap());
}

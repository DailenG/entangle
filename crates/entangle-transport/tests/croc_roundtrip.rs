use entangle_core::RelayTicket;
use entangle_transport::{Croc, Secret};
use std::{fs, time::Duration};

#[tokio::test]
async fn croc_roundtrip_uses_private_relay() {
    let croc = match Croc::locate(None) {
        Ok(croc) => croc,
        Err(error) if std::env::var("ENTANGLE_REQUIRE_CROC").as_deref() != Ok("1") => {
            eprintln!("skipping croc integration test: {error}");
            return;
        }
        Err(error) => panic!("ENTANGLE_REQUIRE_CROC=1 but croc is unavailable: {error}"),
    };
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("payload.txt");
    let output = temp.path().join("received");
    fs::create_dir(&output).unwrap();
    let bytes = b"private local croc roundtrip";
    fs::write(&source, bytes).unwrap();
    let relay_password = Secret::generate();
    let port_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_port = port_listener.local_addr().unwrap().port();
    drop(port_listener);
    let relay = croc
        .start_relay(base_port, relay_password.expose())
        .await
        .unwrap();
    let ticket: RelayTicket = relay.ticket("127.0.0.1");
    let secret = Secret::generate();
    let mut sender = croc.send(&source, &secret, &ticket).await.unwrap();
    sender.ready().await;
    let receiver = croc.receive(&output, &secret, &ticket).await.unwrap();
    let (send_result, receive_result) = tokio::join!(
        sender.wait(Duration::from_secs(30)),
        receiver.wait(Duration::from_secs(30))
    );
    send_result.unwrap();
    receive_result.unwrap();
    let received = fs::read(output.join("payload.txt")).unwrap();
    assert_eq!(received, bytes);
    relay.shutdown().await.unwrap();
}

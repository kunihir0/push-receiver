use crate::codec::{McsCodec, McsMessage};
use crate::error::{Error, Result};
use crate::proto::{DataMessageStanza, HeartbeatAck, LoginRequest};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_util::codec::Framed;
use tracing::{debug, error};

const HOST: &str = "mtalk.google.com";
const PORT: u16 = 5228;

pub async fn connect(
    android_id: u64,
    security_token: u64,
    persistent_ids: Arc<tokio::sync::Mutex<Vec<String>>>,
    sender: mpsc::Sender<DataMessageStanza>,
) -> Result<()> {
    let mut root_cert_store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        root_cert_store
            .add(cert)
            .map_err(|e| Error::Protocol(e.to_string()))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(HOST)
        .map_err(|_| Error::Protocol("Invalid hostname".to_string()))?
        .to_owned();

    let tcp_stream = TcpStream::connect((HOST, PORT)).await?;
    // Omit set_keepalive as it's not consistently available across tokio versions without socket2

    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    let mut framed = Framed::new(tls_stream, McsCodec::new());

    let hex_android_id = format!("{android_id:x}");

    let current_persistent_ids = persistent_ids.lock().await.clone();
    let login_request = LoginRequest {
        adaptive_heartbeat: Some(false),
        auth_service: Some(2),
        auth_token: security_token.to_string(),
        id: "chrome-63.0.3234.0".to_string(),
        domain: "mcs.android.com".to_string(),
        device_id: Some(format!("android-{hex_android_id}")),
        network_type: Some(1),
        resource: android_id.to_string(),
        user: android_id.to_string(),
        use_rmq2: Some(true),
        setting: vec![crate::proto::Setting {
            name: "new_vc".to_string(),
            value: "1".to_string(),
        }],
        received_persistent_id: current_persistent_ids,
        ..Default::default()
    };

    framed.send(McsMessage::LoginRequest(login_request)).await?;

    while let Some(msg) = framed.next().await {
        match msg {
            Ok(McsMessage::LoginResponse(_)) => {
                debug!("MCS login successful");
                persistent_ids.lock().await.clear();
            }
            Ok(McsMessage::HeartbeatPing(_)) => {
                debug!("Received ping, sending ack");
                if let Err(e) = framed
                    .send(McsMessage::HeartbeatAck(HeartbeatAck::default()))
                    .await
                {
                    error!("Failed to send ack: {e}");
                    break;
                }
            }
            Ok(McsMessage::DataMessageStanza(data)) => {
                if let Err(e) = sender.send(data).await {
                    error!("Failed to forward data message: {e}");
                    break;
                }
            }
            Ok(other) => {
                debug!("Received unhandled MCS message: {:?}", other.tag());
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("peer closed connection") || err_str.contains("UnexpectedEof") {
                    debug!("MCS connection closed by peer (expected): {e}");
                } else {
                    error!("MCS protocol error: {e}");
                }
                break;
            }
        }
    }
    debug!("MCS connection closed");

    Ok(())
}

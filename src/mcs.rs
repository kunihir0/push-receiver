use crate::codec::{McsCodec, McsMessage};
use crate::error::{Error, Result};
use crate::proto::{
    DataMessageStanza, Extension, HeartbeatAck, HeartbeatPing, IqStanza, LoginRequest,
    LoginResponse, iq_stanza,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_util::codec::Framed;

const HOST: &str = "mtalk.google.com";
const PORT: u16 = 5228;
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_mins(5);
const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_HEARTBEAT_INTERVAL: Duration = Duration::from_mins(15);
const HEARTBEAT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_ACK_THRESHOLD: usize = 10;
const STREAM_ACK_EXTENSION_ID: i32 = 13;

/// Opens and maintains one authenticated Mobile Connection Server stream.
///
/// # Errors
///
/// Returns an error when the network, TLS, login, heartbeat, or MCS protocol fails.
pub async fn connect(
    android_id: u64,
    security_token: u64,
    persistent_ids: Arc<tokio::sync::Mutex<Vec<String>>>,
    sender: mpsc::Sender<DataMessageStanza>,
) -> Result<()> {
    let tls_stream = connect_tls().await?;
    let mut framed = Framed::new(tls_stream, McsCodec::new());
    let acknowledged_ids = persistent_ids.lock().await.clone();
    framed
        .send(McsMessage::LoginRequest(login_request(
            android_id,
            security_token,
            acknowledged_ids,
        )))
        .await?;

    let mut state = ConnectionState::default();
    loop {
        let Some(message) = next_message(&mut framed, &state).await? else {
            tracing::debug!("MCS connection closed");
            return Ok(());
        };
        state.record_incoming(&message);

        match message {
            McsMessage::LoginResponse(response) => {
                state.heartbeat_interval = login_heartbeat_interval(&response)?;
                persistent_ids.lock().await.clear();
                tracing::debug!(
                    heartbeat_seconds = state.heartbeat_interval.as_secs(),
                    "MCS login successful"
                );
            }
            McsMessage::HeartbeatPing(_) => {
                framed
                    .send(McsMessage::HeartbeatAck(HeartbeatAck {
                        last_stream_id_received: Some(state.last_stream_id_received),
                        ..HeartbeatAck::default()
                    }))
                    .await?;
            }
            McsMessage::HeartbeatAck(_) => {
                tracing::debug!("MCS heartbeat acknowledged");
            }
            McsMessage::DataMessageStanza(data) => {
                let app_data_keys: Vec<_> = data
                    .app_data
                    .iter()
                    .map(|entry| entry.key.as_str())
                    .collect();
                tracing::debug!(
                    category = %data.category,
                    raw_data_bytes = data.raw_data.as_ref().map_or(0, Vec::len),
                    persistent_id_present = data.persistent_id.is_some(),
                    sent = data.sent,
                    app_data_keys = ?app_data_keys,
                    "Received MCS data message"
                );
                let immediate_ack = data.immediate_ack.unwrap_or(false);
                let tracks_delivery = data.persistent_id.is_some();
                sender.send(data).await.map_err(|_| {
                    Error::Protocol("push notification consumer stopped".to_string())
                })?;
                if tracks_delivery {
                    state.unacknowledged_messages += 1;
                }
                if state.should_ack(immediate_ack) {
                    send_stream_ack(&mut framed, state.last_stream_id_received).await?;
                    state.unacknowledged_messages = 0;
                }
            }
            McsMessage::Close(_) => {
                tracing::debug!("MCS requested a reconnect");
                return Ok(());
            }
            McsMessage::StreamErrorStanza(error) => {
                return Err(Error::Protocol(format!(
                    "MCS stream error {}: {}",
                    error.r#type,
                    error.text.as_deref().unwrap_or("no detail")
                )));
            }
            other => {
                tracing::debug!(tag = other.tag(), "Received unhandled MCS message");
            }
        }
    }
}

async fn connect_tls() -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    for certificate in rustls_native_certs::load_native_certs().certs {
        roots
            .add(certificate)
            .map_err(|error| Error::Protocol(error.to_string()))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(HOST)
        .map_err(|_| Error::Protocol("invalid MCS hostname".to_string()))?
        .to_owned();
    let tcp_stream = TcpStream::connect((HOST, PORT)).await?;
    Ok(connector.connect(server_name, tcp_stream).await?)
}

fn login_request(
    android_id: u64,
    security_token: u64,
    persistent_ids: Vec<String>,
) -> LoginRequest {
    LoginRequest {
        adaptive_heartbeat: Some(false),
        auth_service: Some(2),
        auth_token: security_token.to_string(),
        id: "chrome-63.0.3234.0".to_string(),
        domain: "mcs.android.com".to_string(),
        device_id: Some(format!("android-{android_id:x}")),
        network_type: Some(1),
        resource: android_id.to_string(),
        user: android_id.to_string(),
        use_rmq2: Some(true),
        setting: vec![crate::proto::Setting {
            name: "new_vc".to_string(),
            value: "1".to_string(),
        }],
        received_persistent_id: persistent_ids,
        ..LoginRequest::default()
    }
}

async fn next_message(
    framed: &mut Framed<tokio_rustls::client::TlsStream<TcpStream>, McsCodec>,
    state: &ConnectionState,
) -> Result<Option<McsMessage>> {
    match timeout(state.heartbeat_interval, framed.next()).await {
        Ok(Some(message)) => message.map(Some),
        Ok(None) => Ok(None),
        Err(_) => {
            framed
                .send(McsMessage::HeartbeatPing(HeartbeatPing {
                    last_stream_id_received: state
                        .is_logged_in()
                        .then_some(state.last_stream_id_received),
                    ..HeartbeatPing::default()
                }))
                .await?;
            match timeout(HEARTBEAT_RESPONSE_TIMEOUT, framed.next()).await {
                Ok(Some(message)) => message.map(Some),
                Ok(None) => Ok(None),
                Err(_) => Err(Error::Protocol("MCS heartbeat timed out".to_string())),
            }
        }
    }
}

fn login_heartbeat_interval(response: &LoginResponse) -> Result<Duration> {
    if let Some(error) = response.error.as_ref()
        && error.code != 0
    {
        return Err(Error::Protocol(format!(
            "MCS login failed with code {}: {}",
            error.code,
            error.message.as_deref().unwrap_or("no detail")
        )));
    }
    let requested = response
        .heartbeat_config
        .as_ref()
        .and_then(|config| config.interval_ms)
        .and_then(|milliseconds| u64::try_from(milliseconds).ok())
        .map_or(DEFAULT_HEARTBEAT_INTERVAL, Duration::from_millis);
    Ok(requested.clamp(MIN_HEARTBEAT_INTERVAL, MAX_HEARTBEAT_INTERVAL))
}

async fn send_stream_ack(
    framed: &mut Framed<tokio_rustls::client::TlsStream<TcpStream>, McsCodec>,
    last_stream_id_received: i32,
) -> Result<()> {
    framed
        .send(McsMessage::IqStanza(IqStanza {
            r#type: iq_stanza::IqType::Set as i32,
            id: String::new(),
            extension: Some(Extension {
                id: STREAM_ACK_EXTENSION_ID,
                data: Vec::new(),
            }),
            last_stream_id_received: Some(last_stream_id_received),
            ..IqStanza::default()
        }))
        .await
}

#[derive(Debug)]
struct ConnectionState {
    last_stream_id_received: i32,
    unacknowledged_messages: usize,
    heartbeat_interval: Duration,
}

impl ConnectionState {
    fn record_incoming(&mut self, message: &McsMessage) {
        if matches!(message, McsMessage::LoginResponse(_)) {
            self.last_stream_id_received = 1;
        } else if self.is_logged_in() {
            self.last_stream_id_received = self.last_stream_id_received.saturating_add(1);
        }
    }

    const fn is_logged_in(&self) -> bool {
        self.last_stream_id_received > 0
    }

    const fn should_ack(&self, immediate_ack: bool) -> bool {
        immediate_ack || self.unacknowledged_messages >= STREAM_ACK_THRESHOLD
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            last_stream_id_received: 0,
            unacknowledged_messages: 0,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionState, STREAM_ACK_THRESHOLD};

    #[test]
    fn acknowledges_requested_message_immediately() {
        let state = ConnectionState::default();
        assert!(state.should_ack(true));
    }

    #[test]
    fn acknowledges_after_stream_threshold() {
        let state = ConnectionState {
            unacknowledged_messages: STREAM_ACK_THRESHOLD,
            ..ConnectionState::default()
        };
        assert!(state.should_ack(false));
    }
}

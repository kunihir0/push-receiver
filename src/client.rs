use crate::decrypt::decrypt;
use crate::error::Result;
use crate::proto::{AppData, DataMessageStanza};
use crate::register::{FcmRegistration, Keys, register};
use reqwest::Client;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const CHANNEL_CAPACITY: usize = 100;
const MAX_RECONNECT_DELAY_SECONDS: u64 = 15;

/// An incoming push notification.
#[derive(Debug, Clone)]
pub struct Notification {
    /// Decoded payload bytes, or the raw payload when no decryption keys are available.
    pub decrypted: Vec<u8>,
    /// Stable MCS identifier used to suppress redelivery after reconnecting.
    pub persistent_id: Option<String>,
    /// Key-value metadata attached to the MCS message.
    pub app_data: Vec<AppData>,
    /// Sender timestamp in seconds or milliseconds since the Unix epoch.
    pub sent: Option<i64>,
}

/// Configures and starts an FCM push receiver.
#[derive(Debug)]
pub struct PushReceiverBuilder {
    sender_id: String,
    http: Client,
    persistent_ids: Vec<String>,
}

impl PushReceiverBuilder {
    pub(crate) fn new(sender_id: impl Into<String>) -> Self {
        Self {
            sender_id: sender_id.into(),
            http: Client::new(),
            persistent_ids: Vec::new(),
        }
    }

    /// Sets a custom HTTP client.
    #[must_use]
    pub fn http_client(mut self, client: Client) -> Self {
        self.http = client;
        self
    }

    /// Sets identifiers that were processed before the current connection.
    #[must_use]
    pub fn persistent_ids(mut self, ids: Vec<String>) -> Self {
        self.persistent_ids = ids;
        self
    }

    /// Registers a new receiver identity and opens its MCS stream.
    ///
    /// # Errors
    ///
    /// Returns an error if check-in or FCM registration fails.
    pub async fn connect(self) -> Result<(PushReceiver, mpsc::Receiver<Notification>)> {
        let registration = register(&self.http, &self.sender_id).await?;
        let payload_mode = PayloadMode::Decrypt(registration.keys.clone());
        Ok(self.start(registration, payload_mode))
    }

    /// Opens an MCS stream using an existing Android check-in identity.
    ///
    /// Payloads are forwarded without Web Push decryption because an Android
    /// FCM identity does not use the browser key material created by [`connect`](Self::connect).
    #[must_use]
    pub fn listen(
        self,
        android_id: u64,
        security_token: u64,
    ) -> (PushReceiver, mpsc::Receiver<Notification>) {
        let registration = existing_registration(android_id, security_token);
        self.start(registration, PayloadMode::Raw)
    }

    fn start(
        self,
        registration: FcmRegistration,
        payload_mode: PayloadMode,
    ) -> (PushReceiver, mpsc::Receiver<Notification>) {
        let (message_tx, message_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (notification_tx, notification_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let persistent_ids = std::sync::Arc::new(tokio::sync::Mutex::new(self.persistent_ids));
        let mut tasks = JoinSet::new();

        spawn_mcs_connection(
            &mut tasks,
            registration.android_id,
            registration.security_token,
            std::sync::Arc::clone(&persistent_ids),
            message_tx,
        );
        spawn_payload_forwarder(
            &mut tasks,
            message_rx,
            notification_tx,
            persistent_ids,
            payload_mode,
        );

        (
            PushReceiver {
                sender_id: self.sender_id,
                registration,
                tasks,
            },
            notification_rx,
        )
    }
}

enum PayloadMode {
    Decrypt(Keys),
    Raw,
}

impl std::fmt::Debug for PayloadMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decrypt(_) => formatter
                .debug_tuple("Decrypt")
                .field(&"<redacted>")
                .finish(),
            Self::Raw => formatter.write_str("Raw"),
        }
    }
}

fn spawn_mcs_connection(
    tasks: &mut JoinSet<()>,
    android_id: u64,
    security_token: u64,
    persistent_ids: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>,
    sender: mpsc::Sender<DataMessageStanza>,
) {
    tasks.spawn(async move {
        let mut retry_count = 0_u64;
        loop {
            if let Err(error) = crate::mcs::connect(
                android_id,
                security_token,
                std::sync::Arc::clone(&persistent_ids),
                sender.clone(),
            )
            .await
            {
                tracing::error!(%error, "MCS connection failed");
            }
            if sender.is_closed() {
                break;
            }

            retry_count = retry_count.saturating_add(1);
            let delay = std::cmp::min(retry_count, MAX_RECONNECT_DELAY_SECONDS);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    });
}

fn spawn_payload_forwarder(
    tasks: &mut JoinSet<()>,
    mut messages: mpsc::Receiver<DataMessageStanza>,
    notifications: mpsc::Sender<Notification>,
    persistent_ids: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>,
    payload_mode: PayloadMode,
) {
    tasks.spawn(async move {
        while let Some(message) = messages.recv().await {
            if is_duplicate(&message, &persistent_ids).await {
                tracing::debug!(
                    persistent_id_present = message.persistent_id.is_some(),
                    "Ignoring duplicate MCS message"
                );
                continue;
            }
            let Some(payload) = decode_payload(&message, &payload_mode) else {
                let app_data_keys: Vec<_> = message
                    .app_data
                    .iter()
                    .map(|entry| entry.key.as_str())
                    .collect();
                tracing::warn!(
                    raw_data_present = message.raw_data.is_some(),
                    app_data_keys = ?app_data_keys,
                    "MCS message had no decodable payload"
                );
                continue;
            };
            let notification = Notification {
                decrypted: payload,
                persistent_id: message.persistent_id,
                app_data: message.app_data,
                sent: message.sent,
            };
            if notifications.send(notification).await.is_err() {
                break;
            }
        }
    });
}

async fn is_duplicate(
    message: &DataMessageStanza,
    persistent_ids: &tokio::sync::Mutex<Vec<String>>,
) -> bool {
    let Some(id) = message.persistent_id.as_ref() else {
        return false;
    };
    let mut ids = persistent_ids.lock().await;
    if ids.contains(id) {
        true
    } else {
        ids.push(id.clone());
        false
    }
}

fn decode_payload(message: &DataMessageStanza, mode: &PayloadMode) -> Option<Vec<u8>> {
    match mode {
        // Android FCM data messages can carry their complete payload in app_data.
        // Forward an empty byte buffer so callers can still inspect that metadata.
        PayloadMode::Raw => Some(message.raw_data.clone().unwrap_or_default()),
        PayloadMode::Decrypt(keys) => {
            let raw_data = message.raw_data.as_ref()?;
            decode_encrypted_payload(message, raw_data, keys)
        }
    }
}

fn decode_encrypted_payload(
    message: &DataMessageStanza,
    raw_data: &[u8],
    keys: &Keys,
) -> Option<Vec<u8>> {
    if message.app_data.is_empty() {
        return Some(raw_data.to_vec());
    }
    let crypto_key = app_data_value(message, "crypto-key")?;
    let salt = app_data_value(message, "encryption")?;
    match decrypt(
        crypto_key,
        salt,
        &keys.auth_secret,
        &keys.private_key,
        raw_data,
    ) {
        Ok(payload) => Some(payload),
        Err(error) => {
            tracing::warn!(%error, "Failed to decrypt push message");
            None
        }
    }
}

fn app_data_value<'a>(message: &'a DataMessageStanza, key: &str) -> Option<&'a str> {
    message
        .app_data
        .iter()
        .find(|data| data.key == key)
        .map(|data| data.value.as_str())
}

fn existing_registration(android_id: u64, security_token: u64) -> FcmRegistration {
    FcmRegistration {
        token: String::new(),
        android_id,
        security_token,
        app_id: String::new(),
        keys: Keys {
            private_key: String::new(),
            public_key: String::new(),
            auth_secret: String::new(),
        },
        fcm: serde_json::Value::Null,
    }
}

/// Owns a running MCS connection and its forwarding task.
#[derive(Debug)]
pub struct PushReceiver {
    sender_id: String,
    registration: FcmRegistration,
    tasks: JoinSet<()>,
}

impl PushReceiver {
    /// Creates a receiver builder for the supplied FCM sender ID.
    #[must_use]
    pub fn builder(sender_id: impl Into<String>) -> PushReceiverBuilder {
        PushReceiverBuilder::new(sender_id)
    }

    /// Returns the FCM registration associated with this receiver.
    #[must_use]
    pub fn registration(&self) -> &FcmRegistration {
        &self.registration
    }

    /// Returns the configured FCM sender ID.
    #[must_use]
    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }
}

impl Drop for PushReceiver {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use super::{PayloadMode, decode_payload};
    use crate::proto::{AppData, DataMessageStanza};

    #[test]
    fn forwards_app_data_only_android_message() {
        let message = DataMessageStanza {
            from: "sender".to_string(),
            category: "package".to_string(),
            app_data: vec![AppData {
                key: "body".to_string(),
                value: r#"{"type":"server"}"#.to_string(),
            }],
            ..DataMessageStanza::default()
        };

        assert_eq!(
            decode_payload(&message, &PayloadMode::Raw),
            Some(Vec::new())
        );
    }
}

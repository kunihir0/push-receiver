use crate::decrypt::decrypt;
use crate::error::Result;
use crate::proto::AppData;
use crate::register::{FcmRegistration, register};
use reqwest::Client;
use tokio::sync::mpsc;

/// An incoming push notification.
#[derive(Debug, Clone)]
pub struct Notification {
    pub decrypted: Vec<u8>,
    pub persistent_id: Option<String>,
    pub app_data: Vec<AppData>,
}

/// A builder for constructing a `PushReceiver`.
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

    /// Sets the list of previously received persistent IDs for deduplication.
    #[must_use]
    pub fn persistent_ids(mut self, ids: Vec<String>) -> Self {
        self.persistent_ids = ids;
        self
    }

    /// Builds and connects the `PushReceiver`.
    ///
    /// This orchestrates the checkin, registration, and persistent MCS connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkin or registration process fails.
    pub async fn connect(self) -> Result<(PushReceiver, mpsc::Receiver<Notification>)> {
        let registration = register(&self.http, &self.sender_id).await?;

        let (tx, mut rx) = mpsc::channel(100);
        let (decrypted_tx, decrypted_rx) = mpsc::channel(100);

        // Spawn MCS connection task
        let android_id = registration.android_id;
        let security_token = registration.security_token;
        let keys = registration.keys.clone();
        let persistent_ids = std::sync::Arc::new(tokio::sync::Mutex::new(self.persistent_ids));

        let mcs_persistent_ids = persistent_ids.clone();
        tokio::spawn(async move {
            let mut retry_count = 0;
            loop {
                if let Err(e) = crate::mcs::connect(
                    android_id,
                    security_token,
                    mcs_persistent_ids.clone(),
                    tx.clone(),
                )
                .await
                {
                    tracing::error!("MCS connection failed: {e}");
                }

                retry_count += 1;
                let timeout = std::cmp::min(retry_count, 15);
                tokio::time::sleep(std::time::Duration::from_secs(timeout)).await;
            }
        });

        // Spawn decryption task
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Some(ref id) = msg.persistent_id {
                    let mut ids = persistent_ids.lock().await;
                    if ids.contains(id) {
                        // Skip duplicate
                        continue;
                    }
                    ids.push(id.clone());
                }

                let Some(raw_data) = msg.raw_data else {
                    continue;
                };
                if msg.app_data.is_empty() {
                    // Try to send raw bytes if unencrypted
                    let _ = decrypted_tx
                        .send(Notification {
                            decrypted: raw_data,
                            persistent_id: msg.persistent_id,
                            app_data: msg.app_data,
                        })
                        .await;
                    continue;
                }

                let crypto_key = msg.app_data.iter().find(|d| d.key == "crypto-key");
                let salt = msg.app_data.iter().find(|d| d.key == "encryption");

                if let (Some(crypto_key), Some(salt)) = (crypto_key, salt) {
                    match decrypt(
                        &crypto_key.value,
                        &salt.value,
                        &keys.auth_secret,
                        &keys.private_key,
                        &raw_data,
                    ) {
                        Ok(decrypted) => {
                            if decrypted_tx
                                .send(Notification {
                                    decrypted,
                                    persistent_id: msg.persistent_id,
                                    app_data: msg.app_data,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to decrypt message: {}", e);
                        }
                    }
                } else {
                    tracing::warn!("Message missing crypto-key or salt");
                }
            }
        });

        Ok((
            PushReceiver {
                registration,
                sender_id: self.sender_id,
            },
            decrypted_rx,
        ))
    }

    /// Listens for push notifications using existing FCM credentials without re-registering.
    ///
    /// This skips the checkin and registration phases and directly opens the MCS connection.
    /// Note: Encrypted payloads (which require the ECDH keys generated during registration)
    /// cannot be decrypted using this method and will be yielded as raw encrypted bytes.
    ///
    /// # Errors
    ///
    /// This method does not currently return an error, but returns `Result` for consistency with `connect`.
    #[allow(clippy::unused_async)]
    pub async fn listen(
        self,
        android_id: u64,
        security_token: u64,
    ) -> Result<(PushReceiver, mpsc::Receiver<Notification>)> {
        let (tx, mut rx) = mpsc::channel(100);
        let (decrypted_tx, decrypted_rx) = mpsc::channel(100);

        let persistent_ids = std::sync::Arc::new(tokio::sync::Mutex::new(self.persistent_ids));
        let mcs_persistent_ids = persistent_ids.clone();

        tokio::spawn(async move {
            let mut retry_count = 0;
            loop {
                if let Err(e) = crate::mcs::connect(
                    android_id,
                    security_token,
                    mcs_persistent_ids.clone(),
                    tx.clone(),
                )
                .await
                {
                    tracing::error!("MCS connection failed: {e}");
                }

                retry_count += 1;
                let timeout = std::cmp::min(retry_count, 15);
                tokio::time::sleep(std::time::Duration::from_secs(timeout)).await;
            }
        });

        // Spawn minimal forwarding task
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Some(ref id) = msg.persistent_id {
                    let mut ids = persistent_ids.lock().await;
                    if ids.contains(id) {
                        continue;
                    }
                    ids.push(id.clone());
                }

                // Without the original keys, we can only forward the raw payload.
                // For Rust+ pairing, this is usually just unencrypted JSON (or in app_data).
                #[allow(clippy::manual_unwrap_or_default)]
                let decrypted = match msg.raw_data {
                    Some(data) => data,
                    None => Vec::new(),
                };
                let _ = decrypted_tx
                    .send(Notification {
                        decrypted,
                        persistent_id: msg.persistent_id,
                        app_data: msg.app_data,
                    })
                    .await;
            }
        });

        Ok((
            PushReceiver {
                registration: FcmRegistration {
                    token: String::new(),
                    android_id,
                    security_token,
                    app_id: String::new(),
                    keys: crate::register::Keys {
                        private_key: String::new(),
                        public_key: String::new(),
                        auth_secret: String::new(),
                    },
                    fcm: serde_json::Value::Null,
                },
                sender_id: self.sender_id,
            },
            decrypted_rx,
        ))
    }
}

/// The main FCM Push Receiver.
pub struct PushReceiver {
    sender_id: String,
    registration: FcmRegistration,
}

impl PushReceiver {
    /// Creates a new builder for a `PushReceiver`.
    #[must_use]
    pub fn builder(sender_id: impl Into<String>) -> PushReceiverBuilder {
        PushReceiverBuilder::new(sender_id)
    }

    /// Returns the FCM registration details.
    #[must_use]
    pub fn registration(&self) -> &FcmRegistration {
        &self.registration
    }

    /// Returns the sender ID.
    #[must_use]
    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }
}

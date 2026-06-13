use crate::checkin::checkin;
use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;
use uuid::Uuid;

const REGISTER_URL: &str = "https://android.clients.google.com/c2dm/register3";
const FCM_SUBSCRIBE: &str = "https://fcm.googleapis.com/fcm/connect/subscribe";
const FCM_ENDPOINT: &str = "https://fcm.googleapis.com/fcm/send";

const SERVER_KEY: &[u8] = &[
    0x04, 0x33, 0x94, 0xf7, 0xdf, 0xa1, 0xeb, 0xb1, 0xdc, 0x03, 0xa2, 0x5e, 0x15, 0x71, 0xdb, 0x48,
    0xd3, 0x2e, 0xed, 0xed, 0xb2, 0x34, 0xdb, 0xb7, 0x47, 0x3a, 0x0c, 0x8f, 0xc4, 0xcc, 0xe1, 0x6f,
    0x3c, 0x8c, 0x84, 0xdf, 0xab, 0xb6, 0x66, 0x3e, 0xf2, 0x0c, 0xd4, 0x8b, 0xfe, 0xe3, 0xf9, 0x76,
    0x2f, 0x14, 0x1c, 0x63, 0x08, 0x6a, 0x6f, 0x2d, 0xb1, 0x1a, 0x95, 0xb0, 0xce, 0x37, 0xc0, 0x9c,
    0x6e,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keys {
    pub private_key: String,
    pub public_key: String,
    pub auth_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcmRegistration {
    pub token: String,
    pub android_id: u64,
    pub security_token: u64,
    pub app_id: String,
    pub keys: Keys,
    pub fcm: serde_json::Value,
}

/// Performs GCM/FCM registration.
///
/// # Errors
///
/// Returns an error if HTTP requests, JSON parsing, or cryptography operations fail.
pub async fn register(client: &Client, sender_id: &str) -> Result<FcmRegistration> {
    let app_id = format!("wp:receiver.push.com#{}", Uuid::new_v4());

    let checkin_res = checkin(client, None, None).await?;

    let mut retry = 0;
    let token = loop {
        let server_key_b64 = URL_SAFE_NO_PAD.encode(SERVER_KEY);
        let form = [
            ("app", "org.chromium.linux"),
            ("X-subtype", &app_id),
            ("device", &checkin_res.android_id.to_string()),
            ("sender", &server_key_b64),
        ];

        let auth_header = format!(
            "AidLogin {}:{}",
            checkin_res.android_id, checkin_res.security_token
        );

        let res = client
            .post(REGISTER_URL)
            .header("Authorization", auth_header)
            .form(&form)
            .send()
            .await?
            .text()
            .await?;

        if res.contains("Error") {
            warn!("Register request has failed with {}", res);
            if retry >= 5 {
                return Err(Error::Registration("GCM register has failed".to_string()));
            }
            retry += 1;
            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let token = match res.split('=').nth(1) {
            Some(t) => t.to_string(),
            None => String::new(),
        };
        if token.is_empty() {
            return Err(Error::Registration("Invalid token format".to_string()));
        }
        break token;
    };

    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();

    let mut auth_secret = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut auth_secret);

    let keys = Keys {
        private_key: URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(public.to_encoded_point(false).as_bytes()),
        auth_secret: URL_SAFE_NO_PAD.encode(auth_secret),
    };

    let form = [
        ("authorized_entity", sender_id),
        ("endpoint", &format!("{FCM_ENDPOINT}/{token}")),
        ("encryption_key", &keys.public_key),
        ("encryption_auth", &keys.auth_secret),
    ];

    let fcm_res_str = client
        .post(FCM_SUBSCRIBE)
        .form(&form)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let fcm: serde_json::Value = serde_json::from_str(&fcm_res_str)
        .map_err(|e| Error::Registration(format!("Invalid FCM json: {e}")))?;

    Ok(FcmRegistration {
        token,
        android_id: checkin_res.android_id,
        security_token: checkin_res.security_token,
        app_id,
        keys,
        fcm,
    })
}

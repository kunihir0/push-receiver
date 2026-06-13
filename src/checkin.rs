use crate::error::Result;
use crate::proto::{
    AndroidCheckinProto, AndroidCheckinRequest, AndroidCheckinResponse, ChromeBuildProto,
};
use prost::Message;
use reqwest::Client;

const CHECKIN_URL: &str = "https://android.clients.google.com/checkin";

#[derive(Debug, Clone)]
pub struct CheckinResult {
    pub android_id: u64,
    pub security_token: u64,
}

/// Performs the GCM checkin.
///
/// # Errors
/// Returns an error if the HTTP request or protobuf decoding fails.
#[allow(clippy::cast_possible_wrap)]
pub async fn checkin(
    client: &Client,
    android_id: Option<u64>,
    security_token: Option<u64>,
) -> Result<CheckinResult> {
    let payload = AndroidCheckinRequest {
        user_serial_number: Some(0),
        checkin: AndroidCheckinProto {
            last_checkin_msec: None,
            cell_operator: None,
            sim_operator: None,
            roaming: None,
            user_number: None,
            r#type: Some(3), // DEVICE_CHROME_BROWSER
            chrome_build: Some(ChromeBuildProto {
                platform: Some(2), // PLATFORM_MAC
                chrome_version: Some("63.0.3234.0".to_string()),
                channel: Some(1), // CHANNEL_STABLE
            }),
        },
        version: Some(3),
        id: android_id.map(|id| id as i64),
        security_token,
        ..Default::default()
    };

    let mut body = Vec::new();
    payload.encode(&mut body)?;

    let response = client
        .post(CHECKIN_URL)
        .header("Content-Type", "application/x-protobuf")
        .body(body)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let message = AndroidCheckinResponse::decode(response)?;

    #[allow(clippy::manual_unwrap_or_default)]
    Ok(CheckinResult {
        android_id: match message.android_id {
            Some(id) => id,
            None => 0,
        },
        security_token: match message.security_token {
            Some(token) => token,
            None => 0,
        },
    })
}

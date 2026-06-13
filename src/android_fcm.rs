use crate::checkin::checkin;
use crate::error::{Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

const FIREBASE_INSTALLATIONS_URL: &str =
    "https://firebaseinstallations.googleapis.com/v1/projects/{}/installations";
const REGISTER_URL: &str = "https://android.clients.google.com/c2dm/register3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidFcmRegistration {
    pub gcm: GcmDetails,
    pub fcm: FcmDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcmDetails {
    pub android_id: u64,
    pub security_token: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcmDetails {
    pub token: String,
}

/// Firebase Installation Request payload
#[derive(Serialize)]
struct InstallRequest<'a> {
    fid: String,
    #[serde(rename = "appId")]
    app_id: &'a str,
    #[serde(rename = "authVersion")]
    auth_version: &'a str,
    #[serde(rename = "sdkVersion")]
    sdk_version: &'a str,
}

#[derive(Deserialize)]
struct InstallResponse {
    #[serde(rename = "authToken")]
    auth_token: Option<AuthToken>,
}

#[derive(Deserialize)]
struct AuthToken {
    token: Option<String>,
}

/// Helper for Android specific FCM registration flow.
pub struct AndroidFcm;

impl AndroidFcm {
    /// Performs Android FCM registration.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or invalid response.
    pub async fn register(
        client: &Client,
        api_key: &str,
        project_id: &str,
        gcm_sender_id: &str,
        gms_app_id: &str,
        android_package_name: &str,
        android_package_cert: &str,
    ) -> Result<AndroidFcmRegistration> {
        let installation_auth_token = Self::install_request(
            client,
            api_key,
            project_id,
            gms_app_id,
            android_package_name,
            android_package_cert,
        )
        .await?;

        let checkin_res = checkin(client, None, None).await?;

        let fcm_token = Self::register_request(
            client,
            checkin_res.android_id,
            checkin_res.security_token,
            &installation_auth_token,
            gcm_sender_id,
            gms_app_id,
            android_package_name,
            android_package_cert,
            0,
        )
        .await?;

        Ok(AndroidFcmRegistration {
            gcm: GcmDetails {
                android_id: checkin_res.android_id,
                security_token: checkin_res.security_token,
            },
            fcm: FcmDetails { token: fcm_token },
        })
    }

    async fn install_request(
        client: &Client,
        api_key: &str,
        project_id: &str,
        gms_app_id: &str,
        android_package_name: &str,
        android_package_cert: &str,
    ) -> Result<String> {
        let url = FIREBASE_INSTALLATIONS_URL.replace("{}", project_id);

        let req_body = InstallRequest {
            fid: Self::generate_firebase_fid(),
            app_id: gms_app_id,
            auth_version: "FIS_v2",
            sdk_version: "a:17.0.0",
        };

        let response: InstallResponse = client
            .post(&url)
            .header("Accept", "application/json")
            .header("X-Android-Package", android_package_name)
            .header("X-Android-Cert", android_package_cert)
            .header("x-firebase-client", "android-min-sdk/23 fire-core/20.0.0 device-name/a21snnxx device-brand/samsung device-model/a21s android-installer/com.android.vending fire-android/30 fire-installations/17.0.0 fire-fcm/22.0.0 android-platform/ kotlin/1.9.23 android-target-sdk/34")
            .header("x-firebase-client-log-type", "3")
            .header("x-goog-api-key", api_key)
            .header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 11; SM-A217F Build/RP1A.200720.012)")
            .json(&req_body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        response.auth_token.and_then(|t| t.token).ok_or_else(|| {
            Error::Registration("Failed to get Firebase installation AuthToken".to_string())
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn register_request(
        client: &Client,
        android_id: u64,
        security_token: u64,
        installation_auth_token: &str,
        gcm_sender_id: &str,
        gms_app_id: &str,
        android_package_name: &str,
        android_package_cert: &str,
        retry: u32,
    ) -> Result<String> {
        let auth_header = format!("AidLogin {android_id}:{security_token}");

        let form = [
            ("device", android_id.to_string()),
            ("app", android_package_name.to_string()),
            ("cert", android_package_cert.to_string()),
            ("app_ver", "1".to_string()),
            ("X-subtype", gcm_sender_id.to_string()),
            ("X-app_ver", "1".to_string()),
            ("X-osv", "29".to_string()),
            ("X-cliv", "fiid-21.1.1".to_string()),
            ("X-gmsv", "220217001".to_string()),
            ("X-scope", "*".to_string()),
            (
                "X-Goog-Firebase-Installations-Auth",
                installation_auth_token.to_string(),
            ),
            ("X-gms_app_id", gms_app_id.to_string()),
            ("X-Firebase-Client", "android-min-sdk/23 fire-core/20.0.0 device-name/a21snnxx device-brand/samsung device-model/a21s android-installer/com.android.vending fire-android/30 fire-installations/17.0.0 fire-fcm/22.0.0 android-platform/ kotlin/1.9.23 android-target-sdk/34".to_string()),
            ("X-Firebase-Client-Log-Type", "1".to_string()),
            ("X-app_ver_name", "1".to_string()),
            ("target_ver", "31".to_string()),
            ("sender", gcm_sender_id.to_string()),
        ];

        let res = client
            .post(REGISTER_URL)
            .header("Authorization", auth_header)
            .form(&form)
            .send()
            .await?
            .text()
            .await?;

        if res.contains("Error") {
            if retry >= 5 {
                return Err(Error::Registration("GCM register has failed".to_string()));
            }
            sleep(Duration::from_secs(1)).await;
            return Box::pin(Self::register_request(
                client,
                android_id,
                security_token,
                installation_auth_token,
                gcm_sender_id,
                gms_app_id,
                android_package_name,
                android_package_cert,
                retry + 1,
            ))
            .await;
        }

        res.split('=')
            .nth(1)
            .map(ToString::to_string)
            .ok_or_else(|| Error::Registration("Invalid token format".to_string()))
    }

    #[must_use]
    pub fn generate_firebase_fid() -> String {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use rand::RngCore;

        let mut buf = [0u8; 17];
        rand::rngs::OsRng.fill_bytes(&mut buf);

        // replace the first 4 bits with the constant FID header of 0b0111
        buf[0] = 0b0111_0000 | (buf[0] & 0b0000_1111);

        // encode to base64 and remove padding
        // Since original uses `buf.toString("base64").replace(/=/g, "")`, we use URL_SAFE_NO_PAD.
        // Actually, JS base64 is STANDARD base64 but with replaced padding.
        STANDARD_NO_PAD.encode(buf)
    }
}

# push-receiver

This library provides a native, asynchronous client for receiving push notifications via the Google Cloud Messaging (GCM) and Firebase Cloud Messaging (FCM) infrastructure.

## Architecture

The connection process involves three distinct stages:

1. **Checkin:** Registers the device as an Android/Chrome endpoint with Google's checkin servers to receive an `android_id` and `security_token`.
2. **Registration:** Authorizes the device and subscribes to FCM using the provided `sender_id`, generating P-256 ECDH keys for payload encryption.
3. **MCS (Mobile Connection Server):** Establishes a persistent, multiplexed TLS connection to `mtalk.google.com:5228` using a custom Protobuf wire protocol to receive and acknowledge push messages.

Payload decryption is handled automatically using the Web Push HTTP ECE `aesgcm` scheme.

## Usage

Use the builder pattern to initialize the client and establish the persistent connection.

```rust
use push_receiver::PushReceiver;

#[tokio::main]
async fn main() -> push_receiver::Result<()> {
    // The sender ID of your Firebase project
    let sender_id = "123456789012";

    // Connect to FCM and receive the receiver instance and a message stream
    let (receiver, mut message_stream) = PushReceiver::builder(sender_id)
        .connect()
        .await?;

    println!("Registered with token: {}", receiver.registration().token);

    // Listen for incoming decrypted push notifications
    while let Some(notification) = message_stream.recv().await {
        if let Ok(text) = String::from_utf8(notification.decrypted.clone()) {
            println!("Received message: {}", text);
        } else {
            println!("Received binary message: {} bytes", notification.decrypted.len());
        }
        
        if let Some(id) = notification.persistent_id {
            println!("Message ID: {}", id);
        }
    }

    Ok(())
}
```

## Features

- **Runtime Agnostic:** Uses `tokio` async primitives but does not instantiate its own runtime.
- **Native Crypto:** Implements Web Push ECDH and AES-GCM decryption manually using `p256`, `hkdf`, and `aes-gcm`.
- **Structured Concurrency:** Uses `tokio::spawn` for the background MCS connection and decryption tasks, communicating via `mpsc` channels.
- **Strongly Typed Errors:** Uses `thiserror` for comprehensive, matchable error states.
- **Android FCM Flow:** Includes `AndroidFcm::register` for the alternative Firebase Installation ID (FID) registration flow.

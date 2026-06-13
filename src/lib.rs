#![allow(clippy::module_name_repetitions)]
#![allow(clippy::manual_unwrap_or_default, clippy::manual_unwrap_or)]

pub mod android_fcm;
pub mod checkin;
pub mod client;
pub(crate) mod codec;
pub(crate) mod decrypt;
pub mod error;
pub(crate) mod mcs;
pub mod register;

pub mod proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    include!(concat!(env!("OUT_DIR"), "/checkin_proto.rs"));
    include!(concat!(env!("OUT_DIR"), "/mcs_proto.rs"));
}

pub use android_fcm::AndroidFcm;
pub use client::{Notification, PushReceiver, PushReceiverBuilder};
pub use error::{Error, Result};

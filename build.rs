use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }

    prost_build::compile_protos(
        &[
            "proto/checkin.proto",
            "proto/android_checkin.proto",
            "proto/mcs.proto",
        ],
        &["proto/"],
    )?;

    println!("cargo:rerun-if-changed=proto/");

    Ok(())
}

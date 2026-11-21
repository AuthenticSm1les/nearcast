fn main() {
    // Protocol definitions from Google's Nearby / UKEY2 projects (Apache-2.0).
    prost_build::compile_protos(
        &[
            "proto/device_to_device_messages.proto",
            "proto/offline_wire_formats.proto",
            "proto/securegcm.proto",
            "proto/securemessage.proto",
            "proto/ukey.proto",
            "proto/wire_format.proto",
        ],
        &["proto"],
    )
    .expect("compiling protocol buffers (is protoc installed?)");
}

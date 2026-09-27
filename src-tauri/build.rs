fn main() {
    // The macOS biometric crates statically link Swift bridge code. Linker
    // arguments emitted by dependency build scripts do not reliably reach the
    // final Tauri executable, so add the Swift runtime search paths here.
    // `/usr/lib/swift` resolves the system Swift concurrency runtime, while the
    // Frameworks path supports a bundled runtime if one is needed later.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bin=secretary=-Wl,-rpath,/usr/lib/swift");
        println!(
            "cargo:rustc-link-arg-bin=secretary=-Wl,-rpath,@executable_path/../Frameworks"
        );
    }

    tauri_build::build()
}

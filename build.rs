use std::env;

fn main() {
    // 检查是否是库编译模式
    let is_lib = env::var("CARGO_CRATE_TYPE").map_or(false, |crate_type| {
        crate_type.contains("lib") || crate_type.contains("cdylib") || crate_type.contains("rlib")
    });

    // 设置CRATE_TYPE环境变量
    if is_lib {
        println!("cargo:rustc-env=CRATE_TYPE=lib");
    } else {
        println!("cargo:rustc-env=CRATE_TYPE=bin");
    }

    // 确保在Cargo.toml或源代码变更时重新运行build.rs
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src/");
}
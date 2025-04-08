# 基于环境变量的条件编译

本项目实现了基于环境变量的条件编译功能，可以根据编译目标类型（库或可执行程序）来选择性地编译代码。

## 工作原理

### 1. build.rs 文件

`build.rs` 文件在编译时执行，它会检测当前的编译目标类型，并设置相应的环境变量：

```rust
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
```

### 2. 在代码中使用条件编译

一旦环境变量设置好，就可以在代码中使用 `#[cfg(env = "CRATE_TYPE", value = "lib")]` 或 `#[cfg(env = "CRATE_TYPE", value = "bin")]` 属性来控制代码的编译：

```rust
// 这个函数只在库模式下编译
#[cfg(env = "CRATE_TYPE", value = "lib")]
pub fn lib_only_function() -> &'static str {
    "这个函数只在库模式下可用"
}

// 这个函数只在二进制可执行程序模式下编译
#[cfg(env = "CRATE_TYPE", value = "bin")]
pub fn bin_only_function() -> &'static str {
    "这个函数只在二进制可执行程序模式下可用"
}
```

也可以在函数内部使用条件编译：

```rust
pub fn always_available_function() -> &'static str {
    #[cfg(env = "CRATE_TYPE", value = "lib")]
    {
        return "在库模式下的实现";
    }

    #[cfg(env = "CRATE_TYPE", value = "bin")]
    {
        return "在二进制可执行程序模式下的实现";
    }

    "默认实现"
}
```

## 示例文件

本项目包含以下示例文件，展示了如何使用环境变量条件编译：

1. `src/utils/env_example.rs` - 基本用法示例
2. `src/conditional_example.rs` - 在Python绑定中的应用示例

## 使用场景

这种条件编译方式特别适用于以下场景：

1. 需要同时支持库模式和可执行程序模式的代码
2. Python扩展模块与独立应用程序共享代码库
3. 根据编译目标类型提供不同的功能实现

## 与特性(features)的区别

与使用Cargo特性(features)进行条件编译相比，环境变量条件编译的优势在于：

1. 不需要在Cargo.toml中显式定义特性
2. 自动根据编译目标类型设置环境变量
3. 可以与特性条件编译结合使用，提供更灵活的编译控制
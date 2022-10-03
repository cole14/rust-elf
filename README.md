[![](https://img.shields.io/crates/v/elf.svg)](https://crates.io/crates/elf)
[![](https://img.shields.io/crates/d/elf.svg)](https://crates.io/crates/elf)
[![Build Status](https://github.com/cole14/rust-elf/actions/workflows/rust.yml/badge.svg)](https://github.com/cole14/rust-elf/actions)
[![](https://docs.rs/elf/badge.svg)](https://docs.rs/elf/)

# rust-elf
Pure-Rust library for parsing ELF files

[Documentation](https://docs.rs/elf/)

## Example:
```rust
extern crate elf;

use std::path::PathBuf;

let path = PathBuf::from("/some/file/path");
let file = match elf::File::open_path(&path) {
    Ok(f) => f,
    Err(e) => panic!("Error: {:?}", e),
};

let text_scn = match file.get_section(".text") {
    Some(s) => s,
    None => panic!("Failed to look up .text section"),
};

println!("{:?}", text_scn.data);

```

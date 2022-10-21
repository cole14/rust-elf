[![](https://img.shields.io/crates/v/elf.svg)](https://crates.io/crates/elf)
[![](https://img.shields.io/crates/d/elf.svg)](https://crates.io/crates/elf)
[![Build Status](https://github.com/cole14/rust-elf/actions/workflows/rust.yml/badge.svg)](https://github.com/cole14/rust-elf/actions)
[![](https://docs.rs/elf/badge.svg)](https://docs.rs/elf/)

# rust-elf

The `elf` crate provides a pure-rust interface for reading and parsing ELF object files.

[Documentation](https://docs.rs/elf/)

# Capabilities

### Endian-aware:
This crate properly handles translating between file and host endianness
when parsing the ELF contents.

### Lazy parsing:
This crate strives for lazy evaluation and parsing when possible.
[File::open_stream()][File::open_stream] reads, parses and validates the ELF
File Header, then stops there. All other i/o and parsing is deferred to
being performed on-demand by other methods on [File]. For example,
[File::symbol_table()](File::symbol_table) reads the data for the symbol
table and associated string table then returns them with types like
[SymbolTable](symbol::SymbolTable) and
[StringTable](string_table::StringTable) which simply act as an
interpretation layer on top of `&[u8]`s, where parsing of
[Symbol](symbol::Symbol)s and strings take place only when they are
requested.

### Lazy i/o:
This crate provides two ways of parsing ELF files:
* From a `&[u8]` into which the user has already read the full contents of the file
* From a Read + Seek (such as a [std::file::File]) where file contents are read
  lazily on-demand based on what the user wants to inspect.

These allow you to decide what tradeoff you want to make. If you're going to be working
with the whole file at once, then the byte slice approach is probably worthwhile to minimize
i/o overhead by streaming the whole file into memory at once. If you're only going to
be inspecting part of the file, then the Read + Seek approach would help avoid the
overhead of reading a bunch of unused file data just to parse out a few things.

### No unsafe code:
Many of the other rust ELF parsers out there contain bits of unsafe code
deep down or in dependencies to reinterpret/transmute byte contents as
structures in order to drive zero-copy parsing. They're slick, and there's
typically appropriate checking to validate the assumptions to make that
unsafe code work, but nevertheless it introduces unsafe code blocks (albeit
small ones). This crate strives to serve as an alternate implementation with
zero unsafe code blocks.

# Future plans

**Add no_std option** This would disable the Read + Seek interface and limit
the library to the `&[u8]` parsing impl.

## Example:
```rust
extern crate elf;

fn main() {
    let path = std::path::PathBuf::from("some_file");

    let file_data = std::fs::read(path).expect("Could not read file.").as_slice();

    let mut file = File::open_stream(file_data).expect("Could not parse ELF Header");

    let (symtab, strtab) = file
        .symbol_table()
        .expect("Failed to read symbol table")
        .expect("File contained no symbol table");
    let symbol = symtab.get(30).expect("Failed to get symbol");
    let symbol_name = strtab
        .get(symbol.st_name as usize)
        .expect("Failed to get name from strtab");

    println!("{symbol_name}: {symbol}");
}

```

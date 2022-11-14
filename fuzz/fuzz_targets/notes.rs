#![no_main]

use elf::endian::NativeEndian;
use elf::file::Class;
use elf::note::{Note, NoteIterator};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let (head, tail) = data.split_at(1);

    let iter = NoteIterator::new(NativeEndian, Class::ELF64, head[0] as usize, tail);
    let _: Vec<Note> = iter.collect();
});

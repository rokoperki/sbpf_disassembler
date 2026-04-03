use anyhow::{anyhow, Result};
use goblin::elf::Elf;
use std::collections::HashMap;

pub struct ElfInfo {
    pub text: Vec<u8>,                     // raw .text bytes
    pub text_offset: u64,                  // VMA of .text section start
    pub entry: u64,                        // entry point PC
    pub relocations: HashMap<u64, String>, // insn offset → symbol name
    pub sbpf_version: u8,                  // from e_flags (1, 2, or 3)
}

pub fn parse(bytes: &[u8]) -> Result<ElfInfo> {
    let elf = Elf::parse(bytes)?;

    let mut text = Vec::new();
    let mut text_offset = 0u64;
    let mut relocations = HashMap::new();

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".text" {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                text = bytes[start..end].to_vec();
                text_offset = sh.sh_addr;
            }
        }
    }

    for (_, relocs) in &elf.shdr_relocs {
        for reloc in relocs.iter() {
            let sym_idx = reloc.r_sym;
            if let Some(sym) = elf.dynsyms.get(sym_idx) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    let offset = reloc.r_offset - text_offset;
                    relocations.insert(offset, name.to_string());
                }
            }
        }
    }

    let entry = elf.header.e_entry;
    let sbpf_version = (elf.header.e_flags & 0x3) as u8;

    if text.is_empty() {
        return Err(anyhow!(".text section not found"));
    }

    Ok(ElfInfo {
        text,
        text_offset,
        entry,
        relocations,
        sbpf_version,
    })
}

#[test]
fn test_parse_token() {
    let bytes = std::fs::read("token.so").unwrap();
    let info = parse(&bytes).unwrap();
    assert!(!info.text.is_empty());
    assert!(info.entry > 0);
}

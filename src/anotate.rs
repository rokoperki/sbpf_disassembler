use crate::{cu, decode, elf::ElfInfo, syscalls};
use std::collections::HashSet;

pub struct AnnotatedInsn {
    pub pc: u64,
    pub raw: [u8; 8],
    pub mnemonic: String,
    pub syscall_name: Option<String>,
    pub cu: String,
    pub fn_start: bool,
    pub note: Option<String>,
}

pub fn annotate(elf: &ElfInfo) -> Vec<AnnotatedInsn> {
    let mut fn_starts: HashSet<u64> = HashSet::new();
    fn_starts.insert(elf.entry.saturating_sub(elf.text_offset));

    let mut pc = 0u64;
    while pc + 8 <= elf.text.len() as u64 {
        let bytes = &elf.text[pc as usize..];
        let d = decode::decode(bytes, pc as usize);
        // local call: src==1, mnemonic starts with "call"
        if d.insn.op == 0x85 && d.insn.src == 1 {
            let target = pc + 8 + (d.insn.imm as i64 * 8) as u64;
            fn_starts.insert(target);
        }
        pc += if d.is_wide { 16 } else { 8 };
    }

    let mut result = Vec::new();
    let mut pc = 0u64;
    while pc + 8 <= elf.text.len() as u64 {
        let bytes = &elf.text[pc as usize..];
        let d = decode::decode(bytes, pc as usize);

        // resolve syscall name + CU
        let syscall_name = if d.insn.op == 0x85 && d.insn.src == 0 {
            let hash = d.insn.imm as u32;
            syscalls::lookup(hash)
                .map(|s| s.to_string())
                .or_else(|| elf.relocations.get(&pc).cloned())
        } else if d.insn.op == 0x85 && d.insn.src == 1 {
            elf.relocations.get(&pc).cloned()
        } else {
            None
        };

        let cu = cu::cost(syscall_name.as_deref()).to_string();

        // fn boundary
        let fn_start = fn_starts.contains(&pc);

        // note: reloc annotation only shown when syscall_name didn't already capture it
        let note = if let Some(name) = elf.relocations.get(&pc) {
            if syscall_name.is_none() {
                Some(format!("reloc: {}", name))
            } else {
                None
            }
        } else if is_mem_op(d.insn.op) && (d.insn.dst == 10 || d.insn.src == 10) {
            Some("stack".to_string())
        } else {
            None
        };

        // raw bytes
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&elf.text[pc as usize..pc as usize + 8]);

        result.push(AnnotatedInsn {
            pc,
            raw,
            mnemonic: d.mnemonic,
            syscall_name,
            cu,
            fn_start,
            note,
        });

        pc += if d.is_wide { 16 } else { 8 };
    }
    result
}

fn is_mem_op(op: u8) -> bool {
    matches!(op & 0x07, 0x01 | 0x02 | 0x03)
        || matches!(
            op,
            0x24 | 0x34 | 0x84 | 0x94  // v2 loads
                      | 0x27 | 0x37 | 0x87 | 0x97  // v2 stores imm
                      | 0x2f | 0x3f | 0x8f | 0x9f
        ) // v2 stores reg
}

#[test]
fn test_annotate_nocrash() {
    // minimal valid .text: just an exit instruction
    let elf = ElfInfo {
        text: vec![0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        text_offset: 0,
        entry: 0,
        relocations: std::collections::HashMap::new(),
        sbpf_version: 1,
    };
    let result = annotate(&elf);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].mnemonic, "exit");
    assert!(result[0].fn_start);
}

pub struct Insn {
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub offset: i16,
    pub imm: i32,
}

pub struct DecodedIns {
    pub insn: Insn,
    pub mnemonic: String,
    pub is_wide: bool,
}

fn alu_name(op: u8) -> &'static str {
    match op & 0xf0 {
        0x00 => "add",
        0x10 => "sub",
        0x40 => "or",
        0x50 => "and",
        0x60 => "lsh",
        0x70 => "rsh",
        0xa0 => "xor",
        0xb0 => "mov",
        0xc0 => "arsh",
        0xf0 => "hor",
        _    => "alu?",
    }
}

fn pqr_name(op: u8) -> &'static str {
    match op & 0xe0 {
        0x20 => "uhmul",
        0x40 => "udiv",
        0x60 => "urem",
        0x80 => "lmul",
        0xa0 => "shmul",
        0xc0 => "sdiv",
        0xe0 => "srem",
        _    => "pqr?",
    }
}

fn jmp_name(op: u8) -> &'static str {
    match op & 0xf0 {
        0x10 => "jeq",
        0x20 => "jgt",
        0x30 => "jge",
        0x40 => "jset",
        0x50 => "jne",
        0x60 => "jsgt",
        0x70 => "jsge",
        0xa0 => "jlt",
        0xb0 => "jle",
        0xc0 => "jslt",
        0xd0 => "jsle",
        _    => "jmp?",
    }
}

fn decode_alu(op: u8, suffix: &str, dst: u8, src: u8, imm: i32) -> String {
    let name = alu_name(op);
    if op & 0x08 == 0 {
        format!("{}{} r{}, 0x{:x}", name, suffix, dst, imm)
    } else {
        format!("{}{} r{}, r{}", name, suffix, dst, src)
    }
}

fn decode_pqr(op: u8, dst: u8, src: u8, imm: i32) -> String {
    let name = pqr_name(op);
    let suffix = if op & 0x10 == 0 { "32" } else { "64" };
    if op & 0x08 == 0 {
        format!("{}{} r{}, 0x{:x}", name, suffix, dst, imm)
    } else {
        format!("{}{} r{}, r{}", name, suffix, dst, src)
    }
}

// Format a memory reference, omitting zero offset and showing negative offsets cleanly.
fn mem_ref(base: u8, offset: i16) -> String {
    match offset.cmp(&0) {
        std::cmp::Ordering::Equal   => format!("[r{}]", base),
        std::cmp::Ordering::Greater => format!("[r{}+0x{:x}]", base, offset),
        std::cmp::Ordering::Less    => format!("[r{}-0x{:x}]", base, -(offset as i32)),
    }
}

// Compute absolute jump/call target PC from current pc, insn size, and offset/imm.
fn jmp_target(pc: usize, offset: i16) -> u64 {
    (pc as i64 + 8 + offset as i64 * 8) as u64
}

fn call_target(pc: usize, imm: i32) -> u64 {
    (pc as i64 + 8 + imm as i64 * 8) as u64
}

pub fn decode(bytes: &[u8], pc: usize) -> DecodedIns {
    let insn = Insn {
        op: bytes[0],
        dst: bytes[1] & 0x0f,
        src: (bytes[1] >> 4) & 0x0f,
        offset: i16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        imm: i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
    };

    let mut is_wide = false;

    let mnemonic = match insn.op & 0x07 {
        // ALU32 (class 0x04) — also v2 new-style loads share this class
        0x04 => match insn.op {
            0x24 => format!("ld1b r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            0x34 => format!("ld2b r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            0x84 => format!("ld4b r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            0x94 => format!("ld8b r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            _    => decode_alu(insn.op, "32", insn.dst, insn.src, insn.imm),
        },
        // ALU64 (class 0x07) — also v2 new-style stores share this class
        0x07 => match insn.op {
            0x27 => format!("st1b {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x37 => format!("st2b {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x87 => format!("st4b {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x97 => format!("st8b {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x2f => format!("st1b {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            0x3f => format!("st2b {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            0x8f => format!("st4b {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            0x9f => format!("st8b {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            _    => decode_alu(insn.op, "64", insn.dst, insn.src, insn.imm),
        },
        // PQR (class 0x06)
        0x06 => decode_pqr(insn.op, insn.dst, insn.src, insn.imm),
        // JMP (class 0x05)
        0x05 => match insn.op {
            0x05 => format!("ja 0x{:04x}", jmp_target(pc, insn.offset)),
            0x85 => {
                if insn.src == 0 {
                    format!("syscall 0x{:08x}", insn.imm)
                } else {
                    format!("call 0x{:04x}", call_target(pc, insn.imm))
                }
            }
            0x8d => format!("callx r{}", insn.src),
            0x95 => format!("exit"),
            0x9d => format!("return"),
            _    => {
                let name = jmp_name(insn.op);
                let target = jmp_target(pc, insn.offset);
                if insn.op & 0x08 == 0 {
                    format!("{} r{}, 0x{:x}, 0x{:04x}", name, insn.dst, insn.imm, target)
                } else {
                    format!("{} r{}, r{}, 0x{:04x}", name, insn.dst, insn.src, target)
                }
            }
        },
        // legacy loads (class 0x01)
        0x01 => match insn.op {
            0x61 => format!("ldxw r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            0x69 => format!("ldxh r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            0x71 => format!("ldxb r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            0x79 => format!("ldxdw r{}, {}", insn.dst, mem_ref(insn.src, insn.offset)),
            _    => format!("unknown 0x{:02x}", insn.op),
        },
        // legacy stores imm (class 0x02) and reg (class 0x03)
        0x02 => match insn.op {
            0x62 => format!("stw {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x6a => format!("sth {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x72 => format!("stb {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            0x7a => format!("stdw {}, {}", mem_ref(insn.dst, insn.offset), insn.imm),
            _    => format!("unknown 0x{:02x}", insn.op),
        },
        0x03 => match insn.op {
            0x63 => format!("stxw {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            0x6b => format!("stxh {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            0x73 => format!("stxb {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            0x7b => format!("stxdw {}, r{}", mem_ref(insn.dst, insn.offset), insn.src),
            _    => format!("unknown 0x{:02x}", insn.op),
        },
        // lddw (class 0x00, op 0x18)
        0x00 => {
            is_wide = true;
            let upper = i32::from_le_bytes(bytes[12..16].try_into().unwrap());
            let val = ((upper as u64) << 32) | (insn.imm as u32 as u64);
            format!("lddw r{}, 0x{:x}", insn.dst, val)
        }
        _ => format!("unknown 0x{:02x}", insn.op),
    };

    DecodedIns { insn, mnemonic, is_wide }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit() {
        let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "exit");
    }

    #[test]
    fn test_ldxw() {
        let bytes = [0x61, 0x21, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "ldxw r1, [r2+0x4]");
    }

    #[test]
    fn test_ldxw_zero_offset() {
        let bytes = [0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "ldxw r1, [r2]");
    }

    #[test]
    fn test_ldxdw_negative_offset() {
        let bytes = [0x79, 0xa6, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "ldxdw r6, [r10-0x8]");
    }

    #[test]
    fn test_add64_reg() {
        let bytes = [0x0f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "add64 r1, r2");
    }

    #[test]
    fn test_mov64_imm() {
        let bytes = [0xb7, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "mov64 r0, 0x5");
    }

    #[test]
    fn test_jeq_imm() {
        // jeq r1, 0x0, target=0x20 (pc=0, offset=3 → 0 + 8 + 3*8 = 0x20)
        let bytes = [0x15, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "jeq r1, 0x0, 0x0020");
    }

    #[test]
    fn test_jeq_reg() {
        let bytes = [0x1d, 0x21, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "jeq r1, r2, 0x0020");
    }

    #[test]
    fn test_ja_target() {
        // ja offset=-12 from pc=0x80 → 0x80 + 8 + (-12)*8 = 0x88 - 0x60 = 0x28
        let bytes = [0x05, 0x00, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0x80).mnemonic, "ja 0x0028");
    }

    #[test]
    fn test_call_target() {
        // call imm=263 from pc=0x1a8 → 0x1a8 + 8 + 263*8 = 0x9e8
        let mut bytes = [0u8; 8];
        bytes[0] = 0x85;
        bytes[1] = 0x10; // src=1 (local call)
        bytes[4..8].copy_from_slice(&263u32.to_le_bytes());
        assert_eq!(decode(&bytes, 0x1a8).mnemonic, "call 0x09e8");
    }

    #[test]
    fn test_udiv64_reg() {
        let bytes = [0x5e, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "udiv64 r1, r2");
    }

    #[test]
    fn test_lddw() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x18;
        bytes[1] = 0x01;
        bytes[4..8].copy_from_slice(&0x0000beefu32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x00080000u32.to_le_bytes());
        let d = decode(&bytes, 0);
        assert_eq!(d.is_wide, true);
        assert_eq!(d.mnemonic, "lddw r1, 0x800000000beef");
    }

    #[test]
    fn test_syscall() {
        let mut bytes = [0u8; 8];
        bytes[0] = 0x85;
        bytes[4..8].copy_from_slice(&0x207559bdu32.to_le_bytes());
        assert_eq!(decode(&bytes, 0).mnemonic, "syscall 0x207559bd");
    }

    #[test]
    fn test_add32_imm() {
        let bytes = [0x04, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "add32 r1, 0xa");
    }

    #[test]
    fn test_stxdw_negative_offset() {
        let bytes = [0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "stxdw [r10-0x8], r1");
    }
}

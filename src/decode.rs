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

pub fn decode(bytes: &[u8], _pc: usize) -> DecodedIns {
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
            0x24 => format!("ld1b r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            0x34 => format!("ld2b r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            0x84 => format!("ld4b r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            0x94 => format!("ld8b r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            _    => decode_alu(insn.op, "32", insn.dst, insn.src, insn.imm),
        },
        // ALU64 (class 0x07) — also v2 new-style stores share this class
        0x07 => match insn.op {
            0x27 => format!("st1b [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x37 => format!("st2b [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x87 => format!("st4b [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x97 => format!("st8b [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x2f => format!("st1b [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            0x3f => format!("st2b [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            0x8f => format!("st4b [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            0x9f => format!("st8b [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            _    => decode_alu(insn.op, "64", insn.dst, insn.src, insn.imm),
        },
        // PQR (class 0x06)
        0x06 => decode_pqr(insn.op, insn.dst, insn.src, insn.imm),
        // JMP (class 0x05)
        0x05 => match insn.op {
            0x05 => format!("ja +{}", insn.offset),
            0x85 => {
                if insn.src == 0 {
                    format!("syscall 0x{:08x}", insn.imm)
                } else {
                    format!("call +{}", insn.imm)
                }
            }
            0x8d => format!("callx r{}", insn.src),
            0x95 => format!("exit"),
            0x9d => format!("return"),
            _    => {
                let name = jmp_name(insn.op);
                if insn.op & 0x08 == 0 {
                    format!("{} r{}, 0x{:x}, +{}", name, insn.dst, insn.imm, insn.offset)
                } else {
                    format!("{} r{}, r{}, +{}", name, insn.dst, insn.src, insn.offset)
                }
            }
        },
        // legacy loads (class 0x01)
        0x01 => match insn.op {
            0x61 => format!("ldxw r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            0x69 => format!("ldxh r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            0x71 => format!("ldxb r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            0x79 => format!("ldxdw r{}, [r{}+0x{:x}]", insn.dst, insn.src, insn.offset),
            _    => format!("unknown 0x{:02x}", insn.op),
        },
        // legacy stores imm (class 0x02) and reg (class 0x03)
        0x02 => match insn.op {
            0x62 => format!("stw [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x6a => format!("sth [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x72 => format!("stb [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            0x7a => format!("stdw [r{}+0x{:x}], {}", insn.dst, insn.offset, insn.imm),
            _    => format!("unknown 0x{:02x}", insn.op),
        },
        0x03 => match insn.op {
            0x63 => format!("stxw [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            0x6b => format!("stxh [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            0x73 => format!("stxb [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
            0x7b => format!("stxdw [r{}+0x{:x}], r{}", insn.dst, insn.offset, insn.src),
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
        let bytes = [0x15, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "jeq r1, 0x0, +3");
    }

    #[test]
    fn test_jeq_reg() {
        let bytes = [0x1d, 0x21, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "jeq r1, r2, +3");
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
    fn test_stxdw() {
        let bytes = [0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&bytes, 0).mnemonic, "stxdw [r10+0xfff8], r1");
    }
}

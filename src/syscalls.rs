use phf::phf_map;

static SYSCALLS: phf::Map<u32, &'static str> = phf_map! {
    0xb6fc1a11u32 => "abort",
    0x686093bbu32 => "sol_panic_",
    0x207559bdu32 => "sol_log_",
    0x5c2a3178u32 => "sol_log_64_",
    0x7ef088cau32 => "sol_log_pubkey",
    0x52ba5096u32 => "sol_log_compute_units_",
    0x9377323cu32 => "sol_create_program_address",
    0x48504a38u32 => "sol_try_find_program_address",
    0x11f49d86u32 => "sol_sha256",
    0xd7793abbu32 => "sol_keccak256",
    0x17e40350u32 => "sol_secp256k1_recover",
    0xd56b5fe9u32 => "sol_get_clock_sysvar",
    0x23a29a61u32 => "sol_get_epoch_schedule_sysvar",
    0xbf7188f6u32 => "sol_get_rent_sysvar",
    0xfdba2b3bu32 => "sol_get_epoch_rewards_sysvar",
    0x717cc4a3u32 => "sol_memcpy_",
    0x434371f8u32 => "sol_memmove_",
    0x3770fb22u32 => "sol_memset_",
    0x5fdcde31u32 => "sol_memcmp_",
    0xadb8efc8u32 => "sol_get_processed_sibling_instruction",
    0x85532d94u32 => "sol_get_stack_height",
    0xa226d3ebu32 => "sol_set_return_data",
    0x5d2245e4u32 => "sol_get_return_data",
    0xa22b9c85u32 => "sol_invoke_signed_c",
    0xd7449092u32 => "sol_invoke_signed_rust",
    0x7317b434u32 => "sol_log_data",
    0x174c5122u32 => "sol_blake3",
    0xaa2607cau32 => "sol_curve_validate_point",
    0xdd1c41a6u32 => "sol_curve_group_op",
    0x60a40880u32 => "sol_curve_multiscalar_mul",
    0x080c98b0u32 => "sol_curve_decompress",
    0xf111a47eu32 => "sol_curve_pairing_map",
    0x3b97b73cu32 => "sol_get_fees_sysvar",
    0x188a0031u32 => "sol_get_last_restart_slot",
    0x83f00e8fu32 => "sol_alloc_free_",
    0xae0c318bu32 => "sol_alt_bn128_group_op",
    0x780e4c15u32 => "sol_big_mod_exp",
    0xc4947c21u32 => "sol_poseidon",
    0x334fd5edu32 => "sol_alt_bn128_compression",
    0x13c1b505u32 => "sol_get_sysvar",
    0x5be92f4au32 => "sol_get_epoch_stake",
};

pub fn lookup(hash: u32) -> Option<&'static str> {
    SYSCALLS.get(&hash).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup() {
        assert_eq!(lookup(0xb6fc1a11u32), Some("abort"));
        assert_eq!(lookup(0x686093bbu32), Some("sol_panic_"));
        assert_eq!(lookup(0x207559bdu32), Some("sol_log_"));
        assert_eq!(lookup(0x5c2a3178u32), Some("sol_log_64_"));
        assert_eq!(lookup(0x7ef088cau32), Some("sol_log_pubkey"));
        assert_eq!(lookup(0x52ba5096u32), Some("sol_log_compute_units_"));
        assert_eq!(lookup(0x9377323cu32), Some("sol_create_program_address"));
        assert_eq!(lookup(0x48504a38u32), Some("sol_try_find_program_address"));
        assert_eq!(lookup(0x11f49d86u32), Some("sol_sha256"));
        assert_eq!(lookup(0xd7793abbu32), Some("sol_keccak256"));
        assert_eq!(lookup(0x17e40350u32), Some("sol_secp256k1_recover"))
    }
}

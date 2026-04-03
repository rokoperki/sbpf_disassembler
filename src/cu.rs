use std::fmt;

pub enum CuCost {
    Fixed(u64),
    Variable(&'static str),
}

impl fmt::Display for CuCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CuCost::Fixed(n) => write!(f, "{} CU", n),
            CuCost::Variable(s) => write!(f, "{} CU", s),
        }
    }
}

pub fn cost(syscall: Option<&str>) -> CuCost {
    match syscall {
        None => CuCost::Fixed(1),
        Some(name) => match name {
            "sol_log_" => CuCost::Variable("100 + 1/byte"),
            "sol_log_64_" => CuCost::Fixed(100),
            "sol_log_pubkey" => CuCost::Fixed(100),
            "sol_log_compute_units_" => CuCost::Fixed(100),
            "sol_log_data" => CuCost::Variable("100 + 1/byte"),
            "sol_sha256" => CuCost::Variable("85 + 1/byte"),
            "sol_keccak256" => CuCost::Variable("85 + 1/byte"),
            "sol_blake3" => CuCost::Variable("85 + 1/byte"),
            "sol_secp256k1_recover" => CuCost::Fixed(25_000),
            "sol_create_program_address" => CuCost::Fixed(1_500),
            "sol_try_find_program_address" => CuCost::Variable("1500 * bumps"),
            "sol_invoke_signed_c" => CuCost::Variable("946 + CPI"),
            "sol_invoke_signed_rust" => CuCost::Variable("946 + CPI"),
            "sol_memcpy_" => CuCost::Variable("10 + 1/byte"),
            "sol_memmove_" => CuCost::Variable("10 + 1/byte"),
            "sol_memset_" => CuCost::Variable("10 + 1/byte"),
            "sol_memcmp_" => CuCost::Variable("10 + 1/byte"),
            "sol_get_clock_sysvar" => CuCost::Fixed(100),
            "sol_get_rent_sysvar" => CuCost::Fixed(100),
            "sol_get_epoch_schedule_sysvar" => CuCost::Fixed(100),
            "sol_get_epoch_rewards_sysvar" => CuCost::Fixed(100),
            "sol_get_fees_sysvar" => CuCost::Fixed(100),
            "sol_get_last_restart_slot" => CuCost::Fixed(100),
            "sol_get_sysvar" => CuCost::Fixed(100),
            "sol_remaining_compute_units" => CuCost::Fixed(100),
            "sol_get_stack_height" => CuCost::Fixed(100),
            "sol_poseidon" => CuCost::Variable("61*n² + 542"),
            "sol_alt_bn128_group_op" => CuCost::Variable("334-36364"),
            "sol_alt_bn128_compression" => CuCost::Variable("30-13610"),
            "sol_big_mod_exp" => CuCost::Variable("190 + n"),
            "sol_curve_validate_point" => CuCost::Variable("159-169"),
            "sol_curve_group_op" => CuCost::Variable("473-521"),
            "sol_curve_multiscalar_mul" => CuCost::Variable("2273-2303"),
            "sol_curve_decompress" => CuCost::Variable("varies"),
            "sol_curve_pairing_map" => CuCost::Variable("varies"),
            "sol_get_epoch_stake" => CuCost::Variable("varies"),
            "sol_set_return_data" => CuCost::Fixed(100),
            "sol_get_return_data" => CuCost::Fixed(100),
            "sol_get_processed_sibling_instruction" => CuCost::Fixed(100),
            "sol_alloc_free_" => CuCost::Fixed(100),
            "abort" => CuCost::Fixed(100),
            "sol_panic_" => CuCost::Fixed(100),
            _ => CuCost::Fixed(100),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regular_insn() {
        assert!(matches!(cost(None), CuCost::Fixed(1)));
    }

    #[test]
    fn test_fixed_syscall() {
        assert!(matches!(
            cost(Some("sol_secp256k1_recover")),
            CuCost::Fixed(25_000)
        ));
        assert!(matches!(
            cost(Some("sol_create_program_address")),
            CuCost::Fixed(1_500)
        ));
        assert!(matches!(cost(Some("sol_log_64_")), CuCost::Fixed(100)));
    }

    #[test]
    fn test_variable_syscall() {
        assert!(matches!(cost(Some("sol_log_")), CuCost::Variable(_)));
        assert!(matches!(cost(Some("sol_memcpy_")), CuCost::Variable(_)));
        assert!(matches!(
            cost(Some("sol_invoke_signed_rust")),
            CuCost::Variable(_)
        ));
    }

    #[test]
    fn test_unknown_syscall() {
        assert!(matches!(cost(Some("unknown_syscall")), CuCost::Fixed(100)));
    }

    #[test]
    fn test_display() {
        assert_eq!(cost(None).to_string(), "1 CU");
        assert_eq!(cost(Some("sol_secp256k1_recover")).to_string(), "25000 CU");
        assert_eq!(cost(Some("sol_log_")).to_string(), "100 + 1/byte CU");
    }
}

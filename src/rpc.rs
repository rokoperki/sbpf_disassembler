use anyhow::{anyhow, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

pub fn fetch_program_elf(rpc_url: &str, address: &str) -> Result<Vec<u8>> {
    let client = RpcClient::new(rpc_url.to_string());
    let pubkey = Pubkey::from_str(address)?;
    let account = client.get_account(&pubkey)?;
    let owner = account.owner;

    if owner == solana_sdk::bpf_loader::id() {
        Ok(account.data)
    } else if owner == solana_sdk::bpf_loader_upgradeable::id() {
        // program account data layout:
        //   4 bytes: enum discriminant (variant = 2 for Program)
        //   32 bytes: programdata_address pubkey
        if account.data.len() < 36 {
            return Err(anyhow!("program account data too short"));
        }
        let pd_bytes: [u8; 32] = account.data[4..36].try_into()?;
        let pd_pubkey = Pubkey::from(pd_bytes);

        let pd_account = client.get_account(&pd_pubkey)?;
        // programdata account layout:
        //   4 bytes: discriminant (variant = 3 for ProgramData)
        //   8 bytes: slot
        //   1 byte:  Option tag for upgrade_authority
        //  32 bytes: upgrade_authority pubkey (if Some)
        // = 45 bytes before ELF
        if pd_account.data.len() < 45 {
            return Err(anyhow!("programdata account too short"));
        }
        Ok(pd_account.data[45..].to_vec())
    } else {
        Err(anyhow!("unknown loader: {}", owner))
    }
}


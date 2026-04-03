mod anotate;
mod cu;
mod decode;
mod elf;
mod rpc;
mod syscalls;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::Write;

const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

#[derive(Parser)]
#[command(name = "sbpf-dump", about = "sBPF disassembler for Solana programs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Dump {
        /// Program address (base58)
        address: Option<String>,

        /// RPC URL
        #[arg(long, default_value = DEFAULT_RPC)]
        rpc: String,

        /// Read ELF from local file instead of RPC
        #[arg(long)]
        file: Option<String>,

        /// Hide CU cost column
        #[arg(long)]
        no_costs: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Dump {
            address,
            rpc,
            file,
            no_costs,
            json,
            output,
        } => {
            let elf_bytes = if let Some(path) = file {
                std::fs::read(&path)?
            } else {
                let addr = address.ok_or_else(|| anyhow::anyhow!("provide <ADDRESS> or --file"))?;
                rpc::fetch_program_elf(&rpc, &addr)?
            };

            let elf_info = elf::parse(&elf_bytes)?;
            let insns = anotate::annotate(&elf_info);

            let mut out: Box<dyn Write> = match output {
                Some(path) => Box::new(std::fs::File::create(&path)?),
                None => Box::new(std::io::stdout()),
            };

            if json {
                write_json(&mut out, &insns, no_costs)?;
            } else {
                write_text(&mut out, &insns, no_costs)?;
            }
        }
    }

    Ok(())
}

fn write_text(out: &mut dyn Write, insns: &[anotate::AnnotatedInsn], no_costs: bool) -> Result<()> {
    for insn in insns {
        if insn.fn_start {
            writeln!(out, "; fn @ 0x{:04x}", insn.pc)?;
        }

        let raw = format!(
            "{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            insn.raw[0], insn.raw[1], insn.raw[2], insn.raw[3],
            insn.raw[4], insn.raw[5], insn.raw[6], insn.raw[7],
        );

        let name = insn.syscall_name.as_deref().unwrap_or("");
        let note = insn.note.as_deref().unwrap_or("");
        let annotation = if !name.is_empty() { name } else { note };

        if no_costs {
            writeln!(out, "0x{:04x}  {}  {:<32}  {}", insn.pc, raw, insn.mnemonic, annotation)?;
        } else {
            writeln!(out, "0x{:04x}  {}  {:<32}  {:<28}  [{}]", insn.pc, raw, insn.mnemonic, annotation, insn.cu)?;
        }
    }
    Ok(())
}

fn write_json(out: &mut dyn Write, insns: &[anotate::AnnotatedInsn], _no_costs: bool) -> Result<()> {
    writeln!(out, "[")?;
    for (i, insn) in insns.iter().enumerate() {
        let comma = if i + 1 < insns.len() { "," } else { "" };
        writeln!(out, "  {{\"pc\": {}, \"mnemonic\": \"{}\", \"syscall\": {}, \"cu\": \"{}\", \"fn_start\": {}, \"note\": {}}}{}",
            insn.pc,
            insn.mnemonic,
            insn.syscall_name.as_ref().map(|s| format!("\"{}\"", s)).unwrap_or("null".to_string()),
            insn.cu,
            insn.fn_start,
            insn.note.as_ref().map(|s| format!("\"{}\"", s)).unwrap_or("null".to_string()),
            comma,
        )?;
    }
    writeln!(out, "]")?;
    Ok(())
}

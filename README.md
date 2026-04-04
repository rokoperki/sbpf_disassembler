# sbpf-dump

sBPF disassembler and static analyzer for Solana programs. Fetches any deployed program from mainnet and outputs annotated assembly — CU costs, syscall names, function boundaries.

## Install

```
cargo install --path .
```

## Usage

```
sbpf-dump dump <PROGRAM_ADDRESS>
sbpf-dump dump --file <path/to/program.so>
```

### Options

| Flag | Description |
|---|---|
| `--rpc <URL>` | RPC endpoint (default: mainnet-beta) |
| `--file <path>` | Read local ELF instead of fetching from RPC |
| `--no-costs` | Hide CU cost column |
| `--json` | Output as JSON |
| `--output <path>` | Write to file instead of stdout |

## Output

```
; fn @ 0x0000
0x0000  79 16 00 00 00 00 00 00  ldxdw r6, [r1]                    [1 CU]
0x0008  bf 17 00 00 00 00 00 00  mov64 r7, r1                      [1 CU]
...
0x0040  85 00 00 00 bd 59 75 20  syscall 0x207559bd  sol_log_       [100 + 1/byte CU]
...
```

Each instruction line shows:
- **PC** — byte offset into `.text`
- **Raw bytes** — 8-byte encoding
- **Mnemonic** — human-readable sBPF assembly
- **Annotation** — syscall name, relocation symbol, or `stack` for `r10` accesses
- **CU cost** — compute units consumed

Function entry points are labeled `; fn @ 0xXXXX`, detected from call targets.

## Features

- Full sBPF instruction decode — all opcode classes (ALU32/64, PQR, JMP, loads/stores, `lddw`, `callx`)
- Syscall resolution — 45+ Murmur3 hashes mapped to names (`sol_log_`, `invoke_signed`, crypto primitives, etc.)
- CU cost per instruction — fixed (1 CU) or variable for syscalls
- Function boundary detection from call graph
- Stack access markers
- Relocation symbol annotations
- JSON output for tooling

## Examples

```sh
# SPL Token
sbpf-dump dump TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

# Local file
sbpf-dump dump --file ./my_program.so --no-costs

# JSON output
sbpf-dump dump TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA --json --output token.json
```

# uniswap-v4-hook-verifier

Zero-dependency Python CLI to **decode Uniswap v4 14-bit Hook permission flags**, **independently verify EIP-1014 `CREATE2` salts**, and calculate **calldata zero-byte gas savings**.

## Why?

In **Uniswap v4**, hook callback permissions (`BEFORE_SWAP`, `AFTER_SWAP`, `BEFORE_ADD_LIQUIDITY`, etc.) are encoded directly into the **lowest 14 bits (`address & 0x3FFF`)** of the hook contract's 20-byte address. Deploying a hook — especially one that *also* carries leading zero bytes (`0x000000...`) to save calldata gas (`12 gas` saved per zero byte on every call) — requires mining a `bytes32` `CREATE2` salt.

Before deploying on mainnet, always verify your mined salt independently offline.

## Usage (Zero Pip Installs Required)

### 1. Verify an EIP-1014 `CREATE2` Salt & Decode Uniswap v4 Flags

```bash
python3 verify_hook.py verify \
  --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C \
  --salt 0x0d554b0b21a05577ab7a1b5c0dbc16f58404482bef4ff4323bb08c8a0c52af51 \
  --init-code-hash 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
```

Output:
```text
Address (EIP-55) : 0x0000E11Ec03A91aB93444Eaa4fB07E83A0EaCc00
Leading Zero Hex : 4 nibbles
Total Zero Bytes : 3 (saves 36 calldata gas / call)
Uniswap v4 Mask  : 0x0c00 (binary 00110000000000)
Active v4 Hooks  : BEFORE_SWAP_FLAG, AFTER_SWAP_FLAG
```

### 2. Decode Any Existing Uniswap v4 Hook Address

```bash
python3 verify_hook.py decode 0x0000E11Ec03A91aB93444Eaa4fB07E83A0EaCc00
```

## Empirical Benchmark: Foundry CPU `HookMiner` vs Single-Block CUDA Keccak-256

Because EIP-1014 `CREATE2` preimages are always exactly **85 bytes** (`0xff || deployer[20] || salt[32] || initCodeHash[32]`), they fit inside a **single 136-byte Keccak-256 rate block** with zero elliptic-curve operations.

| Target Pattern | Difficulty | Expected Hashes | Foundry CPU (~400 KH/s) | NVIDIA L4 CUDA (`1.36 GH/s`) |
| :--- | :---: | ---: | ---: | ---: |
| 14-bit v4 Hook flags only | 14 bits | 16,384 | ~0.04 s | < 0.001 s |
| 14-bit v4 Hook + `0x0000` (4 zeros) | 30 bits | 1.07 B | ~45 min | **~0.8 s** |
| 14-bit v4 Hook + `0x000000` (6 zeros) | 38 bits | 274.9 B | ~8 days | **~3.4 min** |
| `0x0000000000...` (5 zero bytes, -60 gas/call) | 40 bits | 1.10 T | ~32 days | **~13.5 min** |
| 14-bit v4 Hook + `0x0000000` (7 zeros) | 42 bits | 4.40 T | ~127 days | **~54 min** |

## Need High-Bit `CREATE2` / Uniswap v4 Salts Without Renting GPUs?

You can use our zero-trust web verifier & on-demand NVIDIA L4 GPU salt mining tool at **[trxvanity.xyz/create2](https://trxvanity.xyz/create2)** — only your public `deployer` and `initCodeHash` are ever submitted (no private keys or source code required).

## License

MIT

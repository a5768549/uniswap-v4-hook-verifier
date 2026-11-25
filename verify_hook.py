#!/usr/bin/env python3
"""
uniswap-v4-hook-verifier: Zero-dependency Python CLI to decode Uniswap v4 14-bit
Hook address flags, verify EIP-1014 CREATE2 salts, and calculate calldata gas savings.
"""
import argparse
import sys

HOOK_BITS = [
    (13, "BEFORE_INITIALIZE_FLAG"),
    (12, "AFTER_INITIALIZE_FLAG"),
    (11, "BEFORE_SWAP_FLAG"),
    (10, "AFTER_SWAP_FLAG"),
    (9,  "BEFORE_ADD_LIQUIDITY_FLAG"),
    (8,  "AFTER_ADD_LIQUIDITY_FLAG"),
    (7,  "BEFORE_REMOVE_LIQUIDITY_FLAG"),
    (6,  "AFTER_REMOVE_LIQUIDITY_FLAG"),
    (5,  "BEFORE_DONATE_FLAG"),
    (4,  "AFTER_DONATE_FLAG"),
    (3,  "BEFORE_SWAP_RETURN_DELTA_FLAG"),
    (2,  "AFTER_SWAP_RETURN_DELTA_FLAG"),
    (1,  "AFTER_ADD_LIQUIDITY_RETURN_DELTA_FLAG"),
    (0,  "AFTER_REMOVE_LIQUIDITY_RETURN_DELTA_FLAG"),
]

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x000000000000008B, 0x0000000000008089, 0x0000000000008003,
    0x0000000000008002, 0x0000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_M64 = 0xFFFFFFFFFFFFFFFF


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M64


def keccak256(data: bytes) -> bytes:
    padded = bytearray(data) + b"\x01"
    while len(padded) % 136 != 0:
        padded.append(0)
    padded[-1] |= 0x80
    st = [0] * 25
    for off in range(0, len(padded), 136):
        blk = padded[off : off + 136]
        for i in range(17):
            st[i] ^= int.from_bytes(blk[8 * i : 8 * i + 8], "little")
        for rc in _RC:
            c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    st[x + 5 * y] ^= d[x]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(st[x + 5 * y], _ROT[x][y])
            for x in range(5):
                for y in range(5):
                    st[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
            st[0] ^= rc
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


def to_eip55(addr_hex: str) -> str:
    raw = addr_hex.lower().removeprefix("0x")
    h = keccak256(raw.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c in "abcdef" and int(hh, 16) >= 8 else c for c, hh in zip(raw, h))


def compute_create2(deployer: str, salt: str, init_code_hash: str) -> str:
    dep = bytes.fromhex(deployer.lower().removeprefix("0x"))
    slt = bytes.fromhex(salt.lower().removeprefix("0x"))
    inh = bytes.fromhex(init_code_hash.lower().removeprefix("0x"))
    if len(dep) != 20 or len(slt) != 32 or len(inh) != 32:
        raise ValueError("deployer must be 20 bytes, salt and initCodeHash must be 32 bytes")
    return to_eip55(keccak256(b"\xff" + dep + slt + inh)[12:].hex())


def inspect_address(addr: str) -> None:
    clean = to_eip55(addr)
    raw = bytes.fromhex(clean[2:])
    low14 = int.from_bytes(raw[-2:], "big") & 0x3FFF
    zero_bytes = sum(1 for b in raw if b == 0)
    lead_zeros = len(clean[2:]) - len(clean[2:].lstrip("0"))

    print(f"Address (EIP-55) : {clean}")
    print(f"Leading Zero Hex : {lead_zeros} nibbles")
    print(f"Total Zero Bytes : {zero_bytes} (saves {zero_bytes * 12} calldata gas / call)")
    print(f"Uniswap v4 Mask  : 0x{low14:04x} (binary {low14:014b})")
    active = [name for bit, name in HOOK_BITS if (low14 >> bit) & 1]
    print(f"Active v4 Hooks  : {', '.join(active) if active else 'None'}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Decode Uniswap v4 Hook flags & verify EIP-1014 CREATE2 salts.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser("decode", help="Decode Uniswap v4 14-bit hook flags & zero-byte gas savings")
    p_dec.add_argument("address", help="20-byte EVM address (0x...)")

    p_ver = sub.add_parser("verify", help="Independently compute & verify an EIP-1014 CREATE2 deployment")
    p_ver.add_argument("--deployer", required=True, help="Deployer / Factory address (20 bytes)")
    p_ver.add_argument("--salt", required=True, help="CREATE2 bytes32 salt (0x...)")
    p_ver.add_argument("--init-code-hash", required=True, help="keccak256(initCode) bytes32 (0x...)")

    args = ap.parse_args()
    if args.cmd == "decode":
        inspect_address(args.address)
    elif args.cmd == "verify":
        addr = compute_create2(args.deployer, args.salt, args.init_code_hash)
        inspect_address(addr)


if __name__ == "__main__":
    main()

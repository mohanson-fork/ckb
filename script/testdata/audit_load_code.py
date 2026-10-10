#!/usr/bin/env python3
from pathlib import Path
import struct


def addi(rd: int, rs1: int, imm: int) -> int:
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def lui(rd: int, imm20: int) -> int:
    return (imm20 << 12) | (rd << 7) | 0x37


def lbu(rd: int, rs1: int, imm: int) -> int:
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x03


def code_bytes(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


def elf_header(program_header_count: int, entry: int = 0x1000) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    return ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        243,
        1,
        entry,
        64,
        0,
        0,
        64,
        56,
        program_header_count,
        0,
        0,
        0,
    )


def program_header(
    flags: int, offset: int, vaddr: int, file_size: int, memory_size: int
) -> bytes:
    return struct.pack(
        "<IIQQQQQQ",
        1,
        flags,
        offset,
        vaddr,
        vaddr,
        file_size,
        memory_size,
        0x1000,
    )


def make_root() -> bytes:
    words = [
        # ckb_load_cell_data_as_code(0x5000, 0x1000, 0, 12, cell_dep[1]).
        lui(10, 5),
        lui(11, 1),
        addi(12, 0, 0),
        addi(13, 0, 12),
        addi(14, 0, 1),
        addi(15, 0, 3),
        lui(17, 1),
        addi(17, 17, 2091 - 0x1000),
        0x73,
        # Spawn setup: source=cell dep, bounds/place=0, args at 0x3000.
        addi(11, 0, 3),
        addi(12, 0, 0),
        addi(13, 0, 0),
        lui(14, 3),
        lui(17, 1),
        addi(17, 17, 2601 - 0x1000),
    ]
    for _ in range(4):
        words.extend([addi(10, 0, 2), 0x73])
    words.extend(
        [
            # Correctly restored memory has zero at 0x5100. The vulnerable
            # restore reads byte 42 from outside content_size instead.
            lui(5, 5),
            lbu(10, 5, 0x100),
            addi(17, 0, 93),
            0x73,
        ]
    )
    code = code_bytes(words)

    result = bytearray(0x3040)
    result[:64] = elf_header(2)
    result[64:120] = program_header(5, 0x1000, 0x1000, len(code), len(code))
    result[120:176] = program_header(6, 0x3000, 0x3000, 0x40, 0x1000)
    result[0x1000 : 0x1000 + len(code)] = code
    result[0x3000:0x3020] = struct.pack("<QQQQ", 0, 0, 0x3020, 0)
    return bytes(result)


def make_child() -> bytes:
    code = code_bytes(
        [
            addi(10, 0, 0),
            lui(11, 3),
            lui(17, 1),
            addi(17, 17, 2602 - 0x1000),
            0x73,
            addi(10, 0, 0),
            addi(17, 0, 93),
            0x73,
        ]
    )
    result = bytearray(0x2001)
    result[:64] = elf_header(2)
    result[64:120] = program_header(5, 0x1000, 0x1000, len(code), len(code))
    result[120:176] = program_header(6, 0x2000, 0x3000, 1, 0x1000)
    result[0x1000 : 0x1000 + len(code)] = code
    return bytes(result)


def make_dynamic_data() -> bytes:
    data = bytearray(0x1000)
    data[:12] = code_bytes([addi(10, 0, 0), addi(17, 0, 93), 0x73])
    data[0x100] = 42
    return bytes(data)


def main() -> None:
    output = Path(__file__).resolve().parent
    (output / "audit_load_code_root").write_bytes(make_root())
    (output / "audit_load_code_child").write_bytes(make_child())
    (output / "audit_load_code_data").write_bytes(make_dynamic_data())


if __name__ == "__main__":
    main()

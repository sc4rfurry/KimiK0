"""Shared test fixtures for cs_aggregator.

Provides synthetic payloads and TLV data structures that mimic real
CobaltStrike 4.9.1 payloads (validated against prod.profile).
"""

import struct
import pytest

from cs_aggregator.utils.xor_decrypt import xor_single_byte, TLV_HEADER_SIZE


def build_tlv_entry(setting_id: int, data_type: int, value: bytes) -> bytes:
    """Build a single TLV entry in real CS 6-byte BE format.

    Args:
        setting_id: Setting ID (1-78)
        data_type: 1=short, 2=int, 3=data
        value: Raw value bytes (already in big-endian)
    """
    return struct.pack(">HHH", setting_id, data_type, len(value)) + value


def build_short_entry(setting_id: int, value: int) -> bytes:
    """Build a SHORT TLV entry (data_type=1, 2 bytes BE)."""
    return build_tlv_entry(setting_id, 1, struct.pack(">H", value))


def build_int_entry(setting_id: int, value: int) -> bytes:
    """Build an INT TLV entry (data_type=2, 4 bytes BE)."""
    return build_tlv_entry(setting_id, 2, struct.pack(">I", value))


def build_data_entry(setting_id: int, data: bytes) -> bytes:
    """Build a DATA TLV entry (data_type=3, variable-length)."""
    return build_tlv_entry(setting_id, 3, data)


def build_string_entry(setting_id: int, text: str) -> bytes:
    """Build a DATA TLV entry containing a null-terminated string."""
    return build_data_entry(setting_id, text.encode("ascii") + b"\x00")


@pytest.fixture
def sample_config_tlv() -> bytes:
    """Build a synthetic TLV config block mimicking a CS 4.9.1 profile.

    Matches the prod.profile structure:
        - HTTPS beacon on port 443
        - 60s sleep, 37% jitter
        - Domains: auth.winopsupdate.site
        - Indirect syscalls (method 2)
        - NtMapViewOfSection allocator (1)
        - spawnto: dllhost.exe
    """
    entries = b""

    # SETTING_PROTOCOL = 1 (8 = HTTPS)
    entries += build_short_entry(1, 8)
    # SETTING_PORT = 2 (443)
    entries += build_short_entry(2, 443)
    # SETTING_SLEEPTIME = 3 (60000ms)
    entries += build_int_entry(3, 60000)
    # SETTING_MAXGET = 4 (1048576)
    entries += build_int_entry(4, 1048576)
    # SETTING_JITTER = 5 (37%)
    entries += build_short_entry(5, 37)
    # SETTING_MAXDNS = 6 (255)
    entries += build_short_entry(6, 255)
    # SETTING_PUBKEY = 7
    entries += build_data_entry(7, b"\x30" * 256)
    # SETTING_DOMAINS = 8
    entries += build_string_entry(8, "auth.winopsupdate.site,/jquery-3.7.1.min.js")
    # SETTING_USERAGENT = 9
    entries += build_string_entry(9, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    # SETTING_SUBMITURI = 10
    entries += build_string_entry(10, "/jquery-3.7.1.min.js")
    # SETTING_SYSCALL_METHOD = 17 (2 = indirect)
    entries += build_short_entry(17, 2)
    # SETTING_SPAWNTO_X86 = 29
    entries += build_string_entry(29, "%windir%\\syswow64\\dllhost.exe")
    # SETTING_SPAWNTO_X64 = 30
    entries += build_string_entry(30, "%windir%\\sysnative\\dllhost.exe")
    # SETTING_WATERMARK = 37 (987654321)
    entries += build_int_entry(37, 987654321)
    # SETTING_PROCINJ_ALLOCATOR = 52 (1 = NtMapViewOfSection)
    entries += build_short_entry(52, 1)
    # SETTING_EXIT_FUNK = 55 (1 = ExitThread)
    entries += build_short_entry(55, 1)
    # SETTING_HTTP_NO_COOKIES = 50 (1)
    entries += build_short_entry(50, 1)

    # Null terminator (6 bytes of 0x00)
    entries += b"\x00" * TLV_HEADER_SIZE

    return entries


@pytest.fixture
def sample_config_encrypted(sample_config_tlv: bytes) -> bytes:
    """XOR-encrypt the sample TLV config block with key 0x2E."""
    return xor_single_byte(sample_config_tlv, 0x2E)


@pytest.fixture
def sample_minimal_pe() -> bytes:
    """Build a minimal valid PE (x64) for testing section parsing.

    Has a valid DOS header, PE signature, and 3 sections (.text, .data, .reloc).
    Uses 'OICA' magic instead of 'MZ' to test spoofed header support.
    """
    # DOS header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:4] = b"OICA"  # Spoofed magic (instead of MZ)
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew -> PE header at offset 64

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF file header (20 bytes)
    coff_header = struct.pack("<HHIIIHH",
        0x8664,  # Machine: AMD64
        3,       # NumberOfSections
        0x60000000,  # TimeDateStamp (fake)
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        240,     # SizeOfOptionalHeader (PE32+ = 240)
        0x2022,  # Characteristics: DLL + LARGE_ADDRESS_AWARE
    )

    # Optional header (PE32+, 240 bytes)
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x20B)   # Magic: PE32+
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt_header, 24, 0x180000000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)   # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x50000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)   # SizeOfHeaders
    struct.pack_into("<I", opt_header, 108, 16)      # NumberOfRvaAndSizes

    # Section headers (3 sections, 40 bytes each)
    sections = bytearray()

    # .text section
    sec_text = bytearray(40)
    sec_text[0:5] = b".text"
    struct.pack_into("<I", sec_text, 8, 0x20000)   # VirtualSize
    struct.pack_into("<I", sec_text, 12, 0x1000)    # VirtualAddress
    struct.pack_into("<I", sec_text, 16, 0x20000)   # SizeOfRawData
    struct.pack_into("<I", sec_text, 20, 0x400)     # PointerToRawData
    struct.pack_into("<I", sec_text, 36, 0x60000020)  # Characteristics: CODE+EXEC+READ
    sections += sec_text

    # .data section
    sec_data = bytearray(40)
    sec_data[0:5] = b".data"
    struct.pack_into("<I", sec_data, 8, 0x8000)    # VirtualSize
    struct.pack_into("<I", sec_data, 12, 0x22000)   # VirtualAddress
    struct.pack_into("<I", sec_data, 16, 0x8000)    # SizeOfRawData
    struct.pack_into("<I", sec_data, 20, 0x20400)   # PointerToRawData
    struct.pack_into("<I", sec_data, 36, 0xC0000040)  # Characteristics: INIT+READ+WRITE
    sections += sec_data

    # .reloc section
    sec_reloc = bytearray(40)
    sec_reloc[0:6] = b".reloc"
    struct.pack_into("<I", sec_reloc, 8, 0x2000)   # VirtualSize
    struct.pack_into("<I", sec_reloc, 12, 0x2A000)  # VirtualAddress
    struct.pack_into("<I", sec_reloc, 16, 0x2000)   # SizeOfRawData
    struct.pack_into("<I", sec_reloc, 20, 0x28400)  # PointerToRawData
    struct.pack_into("<I", sec_reloc, 36, 0x42000040)  # Characteristics: DISCARDABLE+READ
    sections += sec_reloc

    # Assemble
    pe = bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + bytes(sections)

    # Pad to total file size (SizeOfImage-ish)
    pe += b"\x00" * (0x2A400 - len(pe))

    return pe


@pytest.fixture
def sample_payload(sample_minimal_pe: bytes, sample_config_encrypted: bytes) -> bytes:
    """Build a synthetic complete payload: loader stub + PE DLL + encrypted config.

    Layout:
        [0x00 - 0x800): Loader stub (NOPs + ROR13 hash pattern)
        [0x800 - ...):   Beacon DLL (OICA magic PE)
        [DLL .data section + offset]: encrypted config block
    """
    # Loader stub: 2048 bytes with recognizable pattern
    loader = b"\xCC" * 512  # INT3 sled
    loader += b"\x0f\xb6\x0f" + b"\xc1\xe9\x08" + b"\x03\xc8"  # ROR13 hash loop signature
    loader += b"\x90" * (2048 - len(loader))  # NOP pad to 2048

    # Inject encrypted config into the PE .data section
    # .data section raw pointer = 0x20400, let's put config near the end
    pe = bytearray(sample_minimal_pe)

    # Ensure PE is large enough
    config_offset_in_pe = 0x20400 + 0x7000  # Near end of .data section
    while len(pe) < config_offset_in_pe + len(sample_config_encrypted) + 256:
        pe += b"\x00" * 4096

    # Inject the encrypted config
    pe[config_offset_in_pe:config_offset_in_pe + len(sample_config_encrypted)] = sample_config_encrypted

    return loader + bytes(pe)

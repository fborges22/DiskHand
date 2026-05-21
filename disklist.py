#!/usr/bin/env python3
# disk_list.py — list partitions from a raw disk image (MBR + GPT)
# Usage: python disk_list.py path/to/disk.img

import sys
import os
import struct
from typing import List, Optional

SECTOR = 512  # default sector size assumption for on-disk metadata

# --- Helpers -----------------------------------------------------------------

def read_at(f, off, n) -> bytes:
    f.seek(off)
    b = f.read(n)
    if len(b) != n:
        raise EOFError("Unexpected EOF reading image")
    return b

def u8(b, off=0):  return b[off]
def u16le(b, off): return struct.unpack_from("<H", b, off)[0]
def u32le(b, off): return struct.unpack_from("<I", b, off)[0]
def u64le(b, off): return struct.unpack_from("<Q", b, off)[0]

def fmt_size(num_bytes: int) -> str:
    units = ["B","KiB","MiB","GiB","TiB","PiB"]
    x = float(num_bytes)
    i = 0
    while x >= 1024.0 and i < len(units)-1:
        x /= 1024.0
        i += 1
    return f"{x:.2f} {units[i]}"

def hexguid(raw16: bytes) -> str:
    # GPT GUIDs are mixed-endian: first 3 fields LE, rest BE
    d1 = struct.unpack("<I", raw16[0:4])[0]
    d2 = struct.unpack("<H", raw16[4:6])[0]
    d3 = struct.unpack("<H", raw16[6:8])[0]
    d4 = raw16[8:10]
    d5 = raw16[10:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"

# Common MBR type names (subset)
MBR_TYPE = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32M",
    0x05: "Extended (CHS)",
    0x06: "FAT16",
    0x07: "HPFS/NTFS/exFAT",
    0x0b: "FAT32 (CHS)",
    0x0c: "FAT32 (LBA)",
    0x0e: "FAT16 (LBA)",
    0x0f: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x12: "Compaq diag",
    0x14: "Hidden FAT16 <32M",
    0x16: "Hidden FAT16",
    0x17: "Hidden HPFS/NTFS",
    0x1b: "Hidden FAT32 (CHS)",
    0x1c: "Hidden FAT32 (LBA)",
    0x1e: "Hidden FAT16 (LBA)",
    0x27: "Win Recovery",
    0x82: "Linux swap",
    0x83: "Linux",
    0x85: "Linux extended",
    0x8e: "Linux LVM",
    0xa5: "FreeBSD",
    0xa6: "OpenBSD",
    0xa8: "Mac OS X",
    0xab: "Mac Boot",
    0xaf: "Apple HFS/HFS+",
    0xee: "GPT protective",
    0xef: "EFI System",
}

# GPT type GUID names (subset)
GPT_TYPE = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System Partition",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux Filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux Swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS/HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "21686148-6449-6e6f-744e-656564454649": "BIOS Boot",
}

class Part:
    def __init__(self, index: str, start_lba: int, end_lba: int, ptype: str, extra: str = ""):
        self.index = index
        self.start_lba = start_lba
        self.end_lba = end_lba
        self.ptype = ptype
        self.extra = extra

    @property
    def sectors(self): return self.end_lba - self.start_lba + 1

    def render(self, bytes_per_sector=SECTOR) -> str:
        sz = self.sectors * bytes_per_sector
        off = self.start_lba * bytes_per_sector
        return (f"{self.index:<6} {self.ptype:<24} "
                f"start {self.start_lba:<10} size {self.sectors:<10} "
                f"({fmt_size(sz):>10})  offset {off}")

# --- MBR parsing --------------------------------------------------------------

def parse_mbr(f) -> (List[Part], Optional[int]):
    mbr = read_at(f, 0, 512)
    if mbr[510:512] != b"\x55\xaa":
        return [], None

    parts: List[Part] = []
    extended_base = None
    # 4 primary entries at offset 446
    for i in range(4):
        e = mbr[446 + i*16: 446 + (i+1)*16]
        boot = u8(e, 0)
        ptype = u8(e, 4)
        start_lba = u32le(e, 8)
        num_sectors = u32le(e, 12)
        if ptype == 0x00 or num_sectors == 0:
            continue
        end_lba = start_lba + num_sectors - 1
        name = MBR_TYPE.get(ptype, f"Type 0x{ptype:02x}")
        extra = "bootable" if boot == 0x80 else ""
        idx = f"p{i+1}"
        parts.append(Part(idx, start_lba, end_lba, name, extra))
        if ptype in (0x05, 0x0F, 0x85):
            extended_base = start_lba  # Beginning of the extended container

    # Follow EBR chain for logical partitions
    if extended_base is not None:
        ebr_lba = extended_base
        logical_idx = 5  # Linux-style numbering: sda5+ for logicals
        while True:
            ebr = read_at(f, ebr_lba * SECTOR, 512)
            if ebr[510:512] != b"\x55\xaa":
                break

            e1 = ebr[446:462]   # first entry: logical
            e2 = ebr[462:478]   # second entry: link to next EBR
            ptype1 = u8(e1, 4)
            slba1  = u32le(e1, 8)
            nsec1  = u32le(e1, 12)
            if ptype1 != 0x00 and nsec1 != 0:
                start = ebr_lba + slba1
                end   = start + nsec1 - 1
                name1 = MBR_TYPE.get(ptype1, f"Type 0x{ptype1:02x}")
                parts.append(Part(f"p{logical_idx}", start, end, name1))
                logical_idx += 1

            # link to next
            ptype2 = u8(e2, 4)
            if ptype2 in (0x05, 0x0F, 0x85):
                rel = u32le(e2, 8)
                ebr_lba = extended_base + rel
            else:
                break

    # Detect protective MBR (GPT)
    gpt_present = any(u8(mbr[446 + i*16: 446 + (i+1)*16], 4) == 0xEE for i in range(4))
    return parts, (1 if gpt_present else None)

# --- GPT parsing --------------------------------------------------------------

def parse_gpt(f) -> List[Part]:
    # GPT header at LBA 1
    hdr = read_at(f, SECTOR, 92)  # at least to size field
    if hdr[0:8] != b"EFI PART":
        return []
    header_size = u32le(hdr, 12)
    if header_size < 92:
        return []
    # Re-read the full header if needed
    hdr = read_at(f, SECTOR, max(92, header_size))

    first_usable = u64le(hdr, 40)
    last_usable  = u64le(hdr, 48)
    entries_lba  = u64le(hdr, 72)
    num_entries  = u32le(hdr, 80)
    entry_size   = u32le(hdr, 84)

    # Read partition entries
    total_pe_bytes = num_entries * entry_size
    buf = read_at(f, entries_lba * SECTOR, total_pe_bytes)

    parts: List[Part] = []
    for i in range(num_entries):
        e = buf[i*entry_size : (i+1)*entry_size]
        ptype_guid = e[0:16]
        if ptype_guid == b"\x00"*16:
            continue  # unused
        first_lba = u64le(e, 32)
        last_lba  = u64le(e, 40)
        name_utf16 = e[56:56+72]  # 36 UTF-16LE chars (72 bytes)
        try:
            name = name_utf16.decode("utf-16le", errors="ignore").rstrip("\x00")
        except Exception:
            name = ""

        type_str = GPT_TYPE.get(hexguid(ptype_guid), hexguid(ptype_guid))
        label = f"{type_str}"
        if name:
            label += f' (“{name}”)'
        parts.append(Part(f"gpt{i+1}", first_lba, last_lba, label))

    return parts

# --- Main ---------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print("Usage: python disk_list.py <disk.img>")
        sys.exit(2)

    path = sys.argv[1]
    st = os.stat(path)
    size = st.st_size

    with open(path, "rb") as f:
        print(f"Disk image: {path}")
        print(f"Size: {fmt_size(size)}  ({size} bytes)")
        print(f"Assumed sector size: {SECTOR} bytes\n")

        mbr_parts, gpt_hint = parse_mbr(f)

        gpt_parts: List[Part] = []
        if gpt_hint:
            try:
                gpt_parts = parse_gpt(f)
            except Exception as e:
                print(f"Note: GPT hinted by protective MBR, but failed to parse GPT: {e}")

        if gpt_parts:
            print("GPT partitions:")
            print("INDEX  TYPE                     START LBA   SIZE (sectors)   (bytes)      OFFSET")
            for p in gpt_parts:
                print(p.render())
        elif mbr_parts:
            print("MBR partitions:")
            print("INDEX  TYPE                     START LBA   SIZE (sectors)   (bytes)      OFFSET")
            for p in mbr_parts:
                print(p.render())
        else:
            print("No partition table found (no valid MBR/GPT signatures).")

if __name__ == "__main__":
    main()

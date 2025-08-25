#!/usr/bin/env python3
import argparse
import os
import re
import struct
from math import ceil

SECTOR_SIZE = 512
ALIGNMENT_SECTORS = (1024 * 1024) // SECTOR_SIZE  # 1 MiB alignment
FAT16_MAX = 2 * 1024 * 1024 * 1024  # 2 GiB
FAT16_MIN = 16 * 1024 * 1024        # ~16 MiB practical floor
FAT_EOC = 0xFFFF

SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)([KMGTP]?i?B?)\s*$", re.IGNORECASE)
UNIT = {
    "": 1, "B": 1,
    "K": 1000, "KB": 1000, "KIB": 1024,
    "M": 1000**2, "MB": 1000**2, "MIB": 1024**2,
    "G": 1000**3, "GB": 1000**3, "GIB": 1024**3,
    "T": 1000**4, "TB": 1000**4, "TIB": 1024**4,
    "P": 1000**5, "PB": 1000**5, "PIB": 1024**5,
}

def parse_size(s: str) -> int:
    m = SIZE_RE.match(s)
    if not m:
        raise ValueError(f"Invalid size: {s!r} (try 64M, 128MiB, 1G, ...)")
    val, unit = m.group(1), (m.group(2) or "").upper()
    if unit not in UNIT:
        # normalize e.g. 'MiB'
        unit = unit.replace("IB", "iB").upper().replace("IB", "IB")
        unit = unit.replace("MIB","MiB").replace("GIB","GiB").upper()
    unit = unit if unit in UNIT else unit.title()
    mult = UNIT.get(unit, None)
    if not mult:
        raise ValueError(f"Unsupported unit: {unit}")
    n = int(round(float(val) * mult))
    if n <= 0:
        raise ValueError("Size must be > 0")
    return n

# ----------------------------
# Low-level writing helpers
# ----------------------------
def pwrite(f, offset, data: bytes):
    f.seek(offset)
    f.write(data)

def zfill_range(f, offset, length):
    f.seek(offset)
    chunk = b"\x00" * min(length, 1024 * 1024)
    remaining = length
    while remaining > 0:
        n = min(remaining, len(chunk))
        f.write(chunk[:n])
        remaining -= n

# ----------------------------
# Partition planning (MBR/DOS)
# ----------------------------
def plan_partitions(sizes_bytes):
    parts = []
    lba = ALIGNMENT_SECTORS
    for i, sz in enumerate(sizes_bytes, start=1):
        sectors = ceil(sz / SECTOR_SIZE)
        # align start to 1MiB boundary
        if lba % ALIGNMENT_SECTORS != 0:
            lba = ALIGNMENT_SECTORS * ceil(lba / ALIGNMENT_SECTORS)
        parts.append({"index": i, "start_lba": lba, "sectors": sectors, "type": 0x06})
        lba += sectors
    total_sectors = lba + ALIGNMENT_SECTORS  # tail pad
    return parts, total_sectors

def chs_dummy():
    # CHS is mostly ignored by modern OSes; use LBA-ish "max" tuples
    # head=254(0xFE), sector=63(0x3F), cylinder=1023(0x3FF) -> encoded bytes FE FF FF
    return bytes([0xFE, 0xFF, 0xFF])

def write_mbr(f, parts, total_sectors):
    # DOS MBR layout with 4 partition entries
    mbr = bytearray(512)
    # Tiny bootstrap (zeros is fine). Add disk signature for good measure.
    struct.pack_into("<I", mbr, 440, 0x12345678)  # disk signature
    # Partition entries (16 bytes each) at 446
    for i, p in enumerate(parts[:4]):
        off = 446 + i * 16
        boot_flag = 0x80 if i == 0 else 0x00  # mark first partition active (optional)
        part_type = p["type"]  # 0x06 = FAT16
        start_lba = p["start_lba"]
        total = p["sectors"]
        entry = bytearray(16)
        entry[0] = boot_flag
        entry[1:4] = chs_dummy()        # start CHS
        entry[4] = part_type
        entry[5:8] = chs_dummy()        # end CHS
        struct.pack_into("<I", entry, 8, start_lba)
        struct.pack_into("<I", entry, 12, total)
        mbr[off:off+16] = entry
    # Signature
    mbr[510:512] = b"\x55\xAA"
    pwrite(f, 0, mbr)
    # Extend/truncate file to full size
    pwrite(f, total_sectors * SECTOR_SIZE - 1, b"\x00")

# ----------------------------
# FAT16 formatter
# ----------------------------
def choose_spc(total_sectors):
    # Heuristic table (512-byte sectors). Keeps cluster size <= 64 KiB.
    # You can tune for your needs. Values are inclusive upper bounds.
    size_bytes = total_sectors * SECTOR_SIZE
    MiB = 1024 * 1024
    if size_bytes <= 32*MiB:  return 2
    if size_bytes <= 64*MiB:  return 4
    if size_bytes <= 128*MiB: return 8
    if size_bytes <= 256*MiB: return 16
    if size_bytes <= 512*MiB: return 32
    if size_bytes <= 1024*MiB: return 64
    return 128  # up to 2 GiB (64 KiB clusters)

def compute_fat16_layout(total_sectors, hidden_sectors):
    bytes_per_sec = SECTOR_SIZE
    sec_per_clus = choose_spc(total_sectors)
    rsvd = 1
    fats = 2
    root_entries = 512
    root_dir_secs = (root_entries * 32 + bytes_per_sec - 1) // bytes_per_sec

    # Iterate to settle FAT size and cluster count
    fat_sz = 1
    for _ in range(16):
        data_secs = total_sectors - (rsvd + root_dir_secs + fats * fat_sz)
        if data_secs <= 0:
            raise ValueError("Partition too small for FAT16 with current parameters.")
        clusters = data_secs // sec_per_clus
        # FAT16 needs 4085..65524 clusters
        if clusters < 4085:
            # too few clusters: decrease sec_per_clus if possible
            if sec_per_clus > 1:
                sec_per_clus //= 2
                if sec_per_clus == 0: sec_per_clus = 1
                continue
            else:
                raise ValueError("Partition too small (not enough clusters) for FAT16.")
        if clusters >= 65525:
            # too many clusters: increase sec_per_clus
            sec_per_clus *= 2
            continue
        needed_entries = clusters + 2  # incl. two reserved
        fat_bytes = needed_entries * 2
        fat_sz_new = (fat_bytes + bytes_per_sec - 1) // bytes_per_sec
        if fat_sz_new == fat_sz:
            break
        fat_sz = fat_sz_new
    # Recompute with settled fat_sz
    data_secs = total_sectors - (rsvd + root_dir_secs + fats * fat_sz)
    clusters = data_secs // sec_per_clus
    # Final sanity
    if not (4085 <= clusters < 65525):
        raise ValueError("Could not find a valid FAT16 layout.")
    return {
        "bytes_per_sec": bytes_per_sec,
        "sec_per_clus": sec_per_clus,
        "rsvd_secs": rsvd,
        "fats": fats,
        "root_entries": root_entries,
        "root_dir_secs": root_dir_secs,
        "fat_sz_secs": fat_sz,
        "total_secs": total_sectors,
        "hidden_secs": hidden_sectors,
        "media": 0xF8,
        "sec_per_trk": 63,
        "num_heads": 255,
        "clusters": clusters,
    }

def mk_boot_sector(b, vol_label=b"NO NAME    ", oem=b"MSWIN4.1"):
    # Ensure sizes
    b = bytearray(b)
    if len(b) != 512:
        b.extend(b"\x00" * (512 - len(b)))
        b[:] = b[:512]
    b[510:512] = b"\x55\xAA"
    return b

def write_fat16_boot_sector(f, offset, lay, volume_label="NO NAME"):
    # Build BPB + extended BPB for FAT16
    bs = bytearray(512)
    # Jump + OEM
    bs[0:3] = b"\xEB\x3C\x90"
    bs[3:11] = (b"MSWIN4.1")  # 8 bytes
    # BPB
    struct.pack_into("<H", bs, 11, lay["bytes_per_sec"])
    struct.pack_into("<B", bs, 13, lay["sec_per_clus"])
    struct.pack_into("<H", bs, 14, lay["rsvd_secs"])
    struct.pack_into("<B", bs, 16, lay["fats"])
    struct.pack_into("<H", bs, 17, lay["root_entries"])
    # TotSec16 or TotSec32
    tot16 = lay["total_secs"] if lay["total_secs"] < 65536 else 0
    struct.pack_into("<H", bs, 19, tot16)
    struct.pack_into("<B", bs, 21, lay["media"])
    struct.pack_into("<H", bs, 22, lay["fat_sz_secs"])
    struct.pack_into("<H", bs, 24, lay["sec_per_trk"])
    struct.pack_into("<H", bs, 26, lay["num_heads"])
    struct.pack_into("<I", bs, 28, lay["hidden_secs"])
    if tot16 == 0:
        struct.pack_into("<I", bs, 32, lay["total_secs"])
    else:
        struct.pack_into("<I", bs, 32, 0)

    # Extended BPB (FAT16)
    struct.pack_into("<B", bs, 36, 0x80)  # Drive number
    struct.pack_into("<B", bs, 37, 0)     # Reserved
    struct.pack_into("<B", bs, 38, 0x29)  # Boot signature
    struct.pack_into("<I", bs, 39, 0x1234ABCD)  # Volume ID
    lbl = (volume_label.upper()[:11]).ljust(11)
    bs[43:54] = lbl.encode("ascii", "replace")
    bs[54:62] = b"FAT16   "

    # (Boot code area left zeroed)
    bs[510:512] = b"\x55\xAA"
    pwrite(f, offset, bs)

def write_fat_tables_and_root(f, part_off, lay):
    bytes_per_sec = lay["bytes_per_sec"]
    rsvd = lay["rsvd_secs"]
    fats = lay["fats"]
    fat_sz = lay["fat_sz_secs"]
    root_dir_secs = lay["root_dir_secs"]

    # FAT region start (after reserved)
    fat0_off = part_off + rsvd * bytes_per_sec

    # FAT initialization: first two 16-bit entries
    fat_first = struct.pack("<H", 0xFFF8) + struct.pack("<H", FAT_EOC)
    fat_total_bytes = fat_sz * bytes_per_sec

    # Write both FATs
    for i in range(fats):
        base = fat0_off + i * fat_total_bytes
        # first few bytes: media/EOC, rest zero
        pwrite(f, base, fat_first)
        zfill_range(f, base + len(fat_first), fat_total_bytes - len(fat_first))

    # Root directory (all zero)
    root_off = fat0_off + fats * fat_total_bytes
    zfill_range(f, root_off, root_dir_secs * bytes_per_sec)

    # Zero the cluster heap (nice to have)
    # Compute start of data region in sectors:
    data_start = lay["rsvd_secs"] + fats * lay["fat_sz_secs"] + lay["root_dir_secs"]
    data_off = part_off + data_start * bytes_per_sec
    data_secs = lay["total_secs"] - data_start
    zfill_range(f, data_off, data_secs * bytes_per_sec)

def format_fat16_partition(f, part_lba_start, part_sectors, volume_label):
    # Compute layout (BPB choices) and write everything
    lay = compute_fat16_layout(total_sectors=part_sectors,
                               hidden_sectors=part_lba_start)
    part_off = part_lba_start * SECTOR_SIZE
    write_fat16_boot_sector(f, part_off, lay, volume_label=volume_label)
    write_fat_tables_and_root(f, part_off, lay)

# ----------------------------
# Main orchestration
# ----------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Create a raw .img with an MBR and N FAT16 partitions (pure Python)."
    )
    ap.add_argument("image", help="Output image path, e.g., disk.img")
    ap.add_argument("sizes", nargs="+", help="Partition sizes, e.g., 64MiB 128MiB 256MiB")
    ap.add_argument("--label-prefix", default="VOL", help="Volume label prefix (max 11 chars total per label)")
    ap.add_argument("--allow-oversize", action="store_true",
                    help="Allow partitions >2GiB (lower compatibility, 64KiB clusters).")
    args = ap.parse_args()

    sizes_bytes = []
    for s in args.sizes:
        n = parse_size(s)
        if not args.allow_oversize and n > FAT16_MAX:
            raise SystemExit(f"{s}: > 2GiB; pass --allow-oversize if you really want this.")
        if n < FAT16_MIN:
            raise SystemExit(f"{s}: too small for robust FAT16 (use >= ~16MiB).")
        sizes_bytes.append(n)

    parts, total_sectors = plan_partitions(sizes_bytes)

    # Create/truncate the image and write MBR
    with open(args.image, "wb+") as f:
        write_mbr(f, parts, total_sectors)
        # Format each partition as FAT16
        for p in parts:
            label = f"{args.label-prefix}{p['index']}" if hasattr(args, "label-prefix") else None
        # Correct label attribute (argparse uses underscore)
    with open(args.image, "rb+") as f:
        for p in parts:
            label = f"{args.label_prefix}{p['index']}" if args.label_prefix else "NO NAME"
            print(f"Formatting partition p{p['index']} @ LBA {p['start_lba']} "
                  f"({p['sectors']} sectors) as FAT16 label={label!r}")
            format_fat16_partition(
                f,
                part_lba_start=p["start_lba"],
                part_sectors=p["sectors"],
                volume_label=label[:11]
            )

    print(f"Done. Wrote {args.image} with {len(parts)} FAT16 partition(s).")

if __name__ == "__main__":
    main()

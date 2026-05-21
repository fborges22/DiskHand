#!/usr/bin/env python3
"""
diskmaptext.py — text-mode FAT cluster map using block-shade characters.

Reads a FAT16 or FAT32 disk image (MBR partitioned or superfloppy) and renders
a cluster-usage map similar to the DOS ScanDisk / DEFRAG visualisation.

Cell shading
------------
  ░  all clusters in the cell are free (unused)
  ▒  the cell contains a mix of free and allocated clusters (partial)
  ▓  all clusters in the cell are allocated (used)
  B  the cell contains at least one bad cluster

Usage
-----
  python diskmaptext.py disk.img                        # first FAT partition, stdout
  python diskmaptext.py disk.img -p 0 -o map.txt        # partition 0, save to file
  python diskmaptext.py disk.img --cols 60 --rows 30    # custom grid size
  python diskmaptext.py disk.img --density 1            # one cell per cluster (detail)
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECTOR_SIZE = 512

FAT_PART_TYPES: Dict[int, str] = {
    0x04: "FAT16 (CHS)",
    0x06: "FAT16 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
}

SHADE_EMPTY   = "░"   # all free
SHADE_PARTIAL = "▒"   # mixed free/used
SHADE_FULL    = "▓"   # all used
SHADE_BAD     = "B"   # contains a bad cluster

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _read(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise IOError(f"Short read at offset {offset}: wanted {size}, got {len(data)}")
    return data


def _fmt(n: int) -> str:
    """Thousands-separated integer."""
    return f"{n:,}"


def _human(nbytes: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if nbytes < 1024 or unit == "TiB":
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{int(nbytes)} B"
        nbytes /= 1024
    return f"{nbytes:.1f} B"

# ---------------------------------------------------------------------------
# MBR partition table
# ---------------------------------------------------------------------------

def _parse_mbr(f) -> List[Tuple[int, int, int, int]]:
    """Return list of (index, ptype, lba_start, sector_count) from MBR."""
    try:
        mbr = _read(f, 0, 512)
    except IOError:
        return []
    if mbr[510:512] != b"\x55\xAA":
        return []
    parts = []
    for i in range(4):
        e = mbr[446 + i * 16: 446 + (i + 1) * 16]
        ptype = e[4]
        lba_start = struct.unpack_from("<I", e, 8)[0]
        sectors = struct.unpack_from("<I", e, 12)[0]
        if ptype != 0 and sectors != 0:
            parts.append((i, ptype, lba_start, sectors))
    return parts

# ---------------------------------------------------------------------------
# BPB / FAT parsing
# ---------------------------------------------------------------------------

def _parse_bpb(boot: bytes) -> dict:
    byts_per_sec  = struct.unpack_from("<H", boot, 11)[0]
    sec_per_clus  = boot[13]
    rsvd_sec_cnt  = struct.unpack_from("<H", boot, 14)[0]
    num_fats      = boot[16]
    root_ent_cnt  = struct.unpack_from("<H", boot, 17)[0]
    tot_sec_16    = struct.unpack_from("<H", boot, 19)[0]
    fatsz_16      = struct.unpack_from("<H", boot, 22)[0]
    tot_sec_32    = struct.unpack_from("<I", boot, 32)[0]
    fatsz_32      = struct.unpack_from("<I", boot, 36)[0] if fatsz_16 == 0 else 0

    fatsz        = fatsz_16 if fatsz_16 else fatsz_32
    tot_sec      = tot_sec_16 if tot_sec_16 else tot_sec_32
    root_dir_sec = ((root_ent_cnt * 32) + (byts_per_sec - 1)) // byts_per_sec
    data_sec     = tot_sec - (rsvd_sec_cnt + num_fats * fatsz + root_dir_sec)
    n_clusters   = data_sec // sec_per_clus if sec_per_clus else 0

    if n_clusters < 4085:
        fat_type = "FAT12"
    elif n_clusters < 65525:
        fat_type = "FAT16"
    else:
        fat_type = "FAT32"

    return {
        "byts_per_sec":    byts_per_sec,
        "sec_per_clus":    sec_per_clus,
        "fatsz":           fatsz,
        "num_fats":        num_fats,
        "first_fat_sec":   rsvd_sec_cnt,
        "cluster_size":    byts_per_sec * sec_per_clus,
        "n_clusters":      n_clusters,
        "fat_type":        fat_type,
    }


def _load_fat(f, part_offset_bytes: int, bpb: dict) -> List[int]:
    fat_off = part_offset_bytes + bpb["first_fat_sec"] * bpb["byts_per_sec"]
    fat_len = bpb["fatsz"] * bpb["byts_per_sec"]
    raw = _read(f, fat_off, fat_len)
    if bpb["fat_type"] == "FAT16":
        count = len(raw) // 2
        return list(struct.unpack_from(f"<{count}H", raw, 0))
    else:  # FAT32
        count = len(raw) // 4
        vals = struct.unpack_from(f"<{count}I", raw, 0)
        return [v & 0x0FFFFFFF for v in vals]


def _classify(fat: List[int], fat_type: str, n_clusters: int) -> List[str]:
    """Return per-data-cluster state: 'free', 'used', or 'bad' for clusters 2..n+1."""
    bad_mark = 0xFFF7 if fat_type == "FAT16" else 0x0FFFFFF7
    states: List[str] = []
    for c in range(2, n_clusters + 2):
        v = fat[c] if c < len(fat) else 0
        if v == 0:
            states.append("free")
        elif v == bad_mark:
            states.append("bad")
        else:
            states.append("used")
    return states

# ---------------------------------------------------------------------------
# Cell grid builder
# ---------------------------------------------------------------------------

def _build_cells(states: List[str], density: int) -> List[str]:
    """
    Group `density` consecutive cluster states into a single display cell.
    Returns a flat list of shade characters (░ ▒ ▓ B).
    """
    cells: List[str] = []
    for i in range(0, len(states), density):
        chunk = states[i: i + density]
        has_bad  = any(s == "bad"  for s in chunk)
        n_used   = sum(1 for s in chunk if s in ("used", "bad"))
        n_free   = sum(1 for s in chunk if s == "free")
        if has_bad:
            cells.append(SHADE_BAD)
        elif n_used == 0:
            cells.append(SHADE_EMPTY)
        elif n_free == 0:
            cells.append(SHADE_FULL)
        else:
            cells.append(SHADE_PARTIAL)
    return cells


def _auto_density(n_clusters: int, cols: int, target_rows: int = 40) -> int:
    target_cells = cols * target_rows
    return max(1, n_clusters // target_cells)

# ---------------------------------------------------------------------------
# Usage bar
# ---------------------------------------------------------------------------

def _usage_bar(used: int, total: int, width: int = 38) -> str:
    """Render a compact ASCII usage bar, e.g. [▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░] 14.7%"""
    pct = used / total if total else 0
    filled = round(pct * width)
    bar = SHADE_FULL * filled + SHADE_EMPTY * (width - filled)
    return f"[{bar}] {pct*100:.1f}%"

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _box(lines_inner: List[str], inner_width: int) -> List[str]:
    """Wrap a list of inner text lines in a Unicode box."""
    h_bar = "─" * (inner_width + 2)
    top = "┌" + h_bar + "┐"
    sep = "├" + h_bar + "┤"
    bot = "└" + h_bar + "┘"

    result: List[str] = [top]
    for raw in lines_inner:
        if raw == "---":          # sentinel for separator
            result.append(sep)
        else:
            pad = inner_width - len(raw)
            result.append("│ " + raw + " " * pad + " │")
    result.append(bot)
    return result


def render_map(
    image_path: str,
    part_info: Optional[Tuple[int, int, int, int]],
    bpb: dict,
    states: List[str],
    density: int,
    cols: int,
    border: bool,
) -> str:
    n_clusters = bpb["n_clusters"]
    used_count  = sum(1 for s in states if s == "used")
    bad_count   = sum(1 for s in states if s == "bad")
    free_count  = sum(1 for s in states if s == "free")

    cells = _build_cells(states, density)
    # Split cells into rows
    map_rows: List[str] = []
    for i in range(0, len(cells), cols):
        row = "".join(cells[i: i + cols])
        map_rows.append(row)

    # ---- header info lines ----
    img_name = os.path.basename(image_path)
    if part_info:
        idx, ptype, lba, sec = part_info
        size_str = _human(sec * SECTOR_SIZE)
        type_str = FAT_PART_TYPES.get(ptype, f"0x{ptype:02X}")
        hdr1 = f"Disk map: {img_name}  Partition {idx} ({type_str},  {size_str})"
    else:
        hdr1 = f"Disk map: {img_name}  (superfloppy / no MBR)"

    hdr2 = (
        f"{bpb['fat_type']}  "
        f"{_fmt(n_clusters)} clusters  "
        f"cluster size {_human(bpb['cluster_size'])}  "
        f"{_fmt(used_count)} used  {_fmt(free_count)} free  {_fmt(bad_count)} bad"
    )

    hdr3 = (
        f"Each cell = {_fmt(density)} cluster{'s' if density != 1 else ''}  "
        f"|  {cols} cols \u00d7 {len(map_rows)} rows  "
        f"|  {_usage_bar(used_count, n_clusters)}"
    )

    legend = (
        f"  {SHADE_EMPTY} unused    "
        f"{SHADE_PARTIAL} partial    "
        f"{SHADE_FULL} used    "
        f"B bad"
    )

    # ---- assemble ----
    if border:
        inner_w = max(
            cols,
            len(hdr1), len(hdr2), len(hdr3), len(legend),
        )
        inner_lines: List[str] = [hdr1, hdr2, hdr3, "---"]
        inner_lines.extend(map_rows)
        inner_lines.extend(["---", legend])
        out_lines = _box(inner_lines, inner_w)
    else:
        out_lines = [hdr1, hdr2, hdr3, ""]
        out_lines.extend(map_rows)
        out_lines.extend(["", legend])

    return "\n".join(out_lines) + "\n"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate a text-mode FAT cluster map (░ ▒ ▓)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("image",      help="Path to disk image")
    ap.add_argument("-p", "--partition", type=int, default=None,
                    help="Partition index (default: first FAT partition)")
    ap.add_argument("-o", "--output",    default=None,
                    help="Output .txt file (default: stdout)")
    ap.add_argument("--cols",    type=int, default=76,
                    help="Map columns / characters per row (default: 76)")
    ap.add_argument("--rows",    type=int, default=None,
                    help="Target number of map rows — sets density automatically")
    ap.add_argument("--density", type=int, default=None,
                    help="Clusters per cell (overrides --rows; default: auto for ~40 rows)")
    ap.add_argument("--no-border", action="store_true",
                    help="Omit the Unicode box-drawing border")
    args = ap.parse_args(argv)

    if args.cols < 1:
        print("--cols must be >= 1", file=sys.stderr)
        return 1

    FAT_TYPES = set(FAT_PART_TYPES.keys())

    with open(args.image, "rb") as f:
        mbr_parts = _parse_mbr(f)
        fat_parts  = [p for p in mbr_parts if p[1] in FAT_TYPES]

        # Resolve target partition
        part_info: Optional[Tuple[int, int, int, int]] = None
        part_offset = 0  # bytes; 0 = superfloppy

        if fat_parts:
            if args.partition is not None:
                part_info = next((p for p in fat_parts if p[0] == args.partition), None)
                if part_info is None:
                    print(f"Partition {args.partition} not found or is not a FAT partition.",
                          file=sys.stderr)
                    return 1
            else:
                part_info = fat_parts[0]
            part_offset = part_info[2] * SECTOR_SIZE
        elif mbr_parts:
            # MBR present but no FAT partitions — try offset 0 anyway (might be superfloppy)
            part_offset = 0

        boot = _read(f, part_offset, 512)
        if boot[510:512] != b"\x55\xAA":
            print("Invalid boot sector signature at target offset.", file=sys.stderr)
            return 1

        bpb = _parse_bpb(boot)

        if bpb["fat_type"] == "FAT12":
            print("FAT12 is not supported.", file=sys.stderr)
            return 1
        if bpb["n_clusters"] == 0:
            print("Invalid BPB: cluster count is 0.", file=sys.stderr)
            return 1

        fat    = _load_fat(f, part_offset, bpb)
        states = _classify(fat, bpb["fat_type"], bpb["n_clusters"])

    # Resolve density
    if args.density is not None:
        density = max(1, args.density)
    elif args.rows is not None:
        density = max(1, bpb["n_clusters"] // (args.cols * args.rows))
    else:
        density = _auto_density(bpb["n_clusters"], args.cols, target_rows=40)

    text = render_map(
        image_path=args.image,
        part_info=part_info,
        bpb=bpb,
        states=states,
        density=density,
        cols=args.cols,
        border=not args.no_border,
    )

    encoded = text.encode("utf-8")

    if args.output:
        with open(args.output, "wb") as out:
            out.write(encoded)
        print(f"Map written to: {args.output}  ({len(encoded):,} bytes)")
    else:
        # Write UTF-8 directly to stdout buffer to avoid encoding errors on Windows
        sys.stdout.buffer.write(encoded)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

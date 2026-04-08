#!/usr/bin/env python3
"""
disk_map.py - render a FAT disk-image cluster map to PNG.

Required arguments:
  --i  input disk .img path
  --o  output .png path

The script reads MBR partitions when present and selects the first FAT partition
by default. It also supports FAT superfloppy images (no partition table).
"""

import argparse
import math
import os
import struct
import zlib

SECTOR_SIZE = 512


def read_at(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise EOFError("Unexpected end of file while reading image")
    return data


def parse_mbr_partitions(f):
    mbr = read_at(f, 0, 512)
    if mbr[510:512] != b"\x55\xAA":
        return []

    parts = []
    for i in range(4):
        e = mbr[446 + i * 16 : 446 + (i + 1) * 16]
        ptype = e[4]
        start_lba = struct.unpack_from("<I", e, 8)[0]
        sectors = struct.unpack_from("<I", e, 12)[0]
        if ptype == 0 or sectors == 0:
            continue
        parts.append(
            {
                "index": i,
                "type": ptype,
                "start_lba": start_lba,
                "sectors": sectors,
            }
        )
    return parts


def parse_bpb(boot):
    byts_per_sec = struct.unpack_from("<H", boot, 11)[0]
    sec_per_clus = boot[13]
    rsvd_sec_cnt = struct.unpack_from("<H", boot, 14)[0]
    num_fats = boot[16]
    root_ent_cnt = struct.unpack_from("<H", boot, 17)[0]
    tot_sec_16 = struct.unpack_from("<H", boot, 19)[0]
    fatsz_16 = struct.unpack_from("<H", boot, 22)[0]
    hidd_sec = struct.unpack_from("<I", boot, 28)[0]
    tot_sec_32 = struct.unpack_from("<I", boot, 32)[0]

    fatsz_32 = struct.unpack_from("<I", boot, 36)[0] if fatsz_16 == 0 else 0
    fatsz = fatsz_16 if fatsz_16 else fatsz_32

    if byts_per_sec == 0 or sec_per_clus == 0 or fatsz == 0:
        raise ValueError("Invalid BPB values")

    root_dir_secs = ((root_ent_cnt * 32) + (byts_per_sec - 1)) // byts_per_sec
    tot_sec = tot_sec_16 if tot_sec_16 else tot_sec_32
    data_secs = tot_sec - (rsvd_sec_cnt + (num_fats * fatsz) + root_dir_secs)
    if data_secs <= 0:
        raise ValueError("Invalid FAT layout")

    count_of_clusters = data_secs // sec_per_clus
    if count_of_clusters < 4085:
        fat_type = "FAT12"
        fat_bits = 12
    elif count_of_clusters < 65525:
        fat_type = "FAT16"
        fat_bits = 16
    else:
        fat_type = "FAT32"
        fat_bits = 32

    first_fat_sector = rsvd_sec_cnt
    first_data_sector = rsvd_sec_cnt + (num_fats * fatsz) + root_dir_secs

    return {
        "byts_per_sec": byts_per_sec,
        "sec_per_clus": sec_per_clus,
        "rsvd_sec_cnt": rsvd_sec_cnt,
        "num_fats": num_fats,
        "root_ent_cnt": root_ent_cnt,
        "root_dir_secs": root_dir_secs,
        "tot_sec": tot_sec,
        "fatsz": fatsz,
        "hidd_sec": hidd_sec,
        "count_of_clusters": count_of_clusters,
        "first_fat_sector": first_fat_sector,
        "first_data_sector": first_data_sector,
        "fat_type": fat_type,
        "fat_bits": fat_bits,
    }


def load_fat_entries(f, part_offset, bpb):
    fat_off = part_offset + bpb["first_fat_sector"] * bpb["byts_per_sec"]
    fat_len = bpb["fatsz"] * bpb["byts_per_sec"]
    fat_raw = read_at(f, fat_off, fat_len)

    if bpb["fat_type"] == "FAT16":
        count = len(fat_raw) // 2
        return list(struct.unpack_from(f"<{count}H", fat_raw, 0))

    if bpb["fat_type"] == "FAT32":
        count = len(fat_raw) // 4
        vals = struct.unpack_from(f"<{count}I", fat_raw, 0)
        return [v & 0x0FFFFFFF for v in vals]

    raise ValueError("FAT12 is not supported by this script")


def classify_clusters(fat_entries, fat_type, cluster_count):
    clusters = []
    free_count = 0
    used_count = 0
    bad_count = 0

    if fat_type == "FAT16":
        bad_marker = 0xFFF7
    else:
        bad_marker = 0x0FFFFFF7

    # Data clusters are numbered from 2.
    for clus in range(2, cluster_count + 2):
        if clus >= len(fat_entries):
            value = 0
        else:
            value = fat_entries[clus]

        if value == 0:
            clusters.append("free")
            free_count += 1
        elif value == bad_marker:
            clusters.append("bad")
            bad_count += 1
        else:
            clusters.append("used")
            used_count += 1

    return clusters, free_count, used_count, bad_count


def png_chunk(chunk_type, data):
    head = struct.pack(">I", len(data)) + chunk_type + data
    crc = zlib.crc32(chunk_type)
    crc = zlib.crc32(data, crc) & 0xFFFFFFFF
    return head + struct.pack(">I", crc)


def write_png_rgb(path, width, height, rgb_bytes):
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

    # PNG scanlines with filter byte = 0 per row.
    stride = width * 3
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        start = y * stride
        raw.extend(rgb_bytes[start : start + stride])

    idat = zlib.compress(bytes(raw), level=9)

    with open(path, "wb") as out:
        out.write(b"\x89PNG\r\n\x1a\n")
        out.write(png_chunk(b"IHDR", ihdr))
        out.write(png_chunk(b"IDAT", idat))
        out.write(png_chunk(b"IEND", b""))


FONT_5X7 = {
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    ":": ["00000", "00100", "00000", "00000", "00100", "00000", "00000"],
    "/": ["00001", "00010", "00100", "01000", "10000", "00000", "00000"],
    "%": ["11001", "11010", "00100", "01000", "10110", "00110", "00000"],
    "(": ["00010", "00100", "01000", "01000", "01000", "00100", "00010"],
    ")": ["01000", "00100", "00010", "00010", "00010", "00100", "01000"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "10000", "11110", "00001", "00001", "11110"],
    "6": ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01110", "10001", "10000", "10111", "10001", "10001", "01110"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "10001", "11001", "10101", "10011", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "=": ["00000", "11111", "00000", "11111", "00000", "00000", "00000"],
}


def choose_portrait_cols(total_clusters, requested_cols):
    if requested_cols is not None:
        return requested_cols
    # Keep width/height around 0.55 for a portrait-oriented map panel.
    return max(32, int(math.sqrt(total_clusters * 0.55)))


def fat_eoc_threshold(fat_type):
    return 0xFFF8 if fat_type == "FAT16" else 0x0FFFFFF8


def cluster_size_bytes(bpb):
    return bpb["byts_per_sec"] * bpb["sec_per_clus"]


def cluster_to_offset(part_offset, bpb, cluster_num):
    first_sector = bpb["first_data_sector"] + (cluster_num - 2) * bpb["sec_per_clus"]
    return part_offset + first_sector * bpb["byts_per_sec"]


def read_cluster_bytes(f, part_offset, bpb, cluster_num):
    return read_at(f, cluster_to_offset(part_offset, bpb, cluster_num), cluster_size_bytes(bpb))


def next_cluster(fat_entries, fat_type, cluster_num):
    if cluster_num <= 1 or cluster_num >= len(fat_entries):
        return None
    nxt = fat_entries[cluster_num]
    if nxt == 0:
        return None
    if nxt >= fat_eoc_threshold(fat_type):
        return None
    return nxt


def get_cluster_chain(fat_entries, fat_type, start_cluster, max_steps):
    chain = []
    seen = set()
    cur = start_cluster

    while cur is not None and len(chain) < max_steps:
        if cur < 2 or cur in seen or cur >= len(fat_entries):
            break
        chain.append(cur)
        seen.add(cur)
        cur = next_cluster(fat_entries, fat_type, cur)
    return chain


def iter_directory_entries(raw_dir_bytes):
    for off in range(0, len(raw_dir_bytes), 32):
        ent = raw_dir_bytes[off : off + 32]
        if len(ent) < 32:
            break
        first = ent[0]
        if first == 0x00:
            break
        if first == 0xE5:
            continue
        attr = ent[11]
        if attr == 0x0F:
            continue
        yield ent


def entry_start_cluster(ent, fat_type):
    lo = struct.unpack_from("<H", ent, 26)[0]
    if fat_type == "FAT32":
        hi = struct.unpack_from("<H", ent, 20)[0]
        return (hi << 16) | lo
    return lo


def root_dir_bytes(f, part_offset, bpb):
    if bpb["fat_type"] == "FAT16":
        root_sector = bpb["first_fat_sector"] + bpb["num_fats"] * bpb["fatsz"]
        root_off = part_offset + root_sector * bpb["byts_per_sec"]
        root_len = bpb["root_dir_secs"] * bpb["byts_per_sec"]
        return read_at(f, root_off, root_len)
    return b""


def directory_chain_bytes(f, part_offset, bpb, fat_entries, start_cluster):
    chain = get_cluster_chain(
        fat_entries,
        bpb["fat_type"],
        start_cluster,
        bpb["count_of_clusters"] + 2,
    )
    chunks = [read_cluster_bytes(f, part_offset, bpb, clus) for clus in chain]
    return b"".join(chunks)


def find_partial_file_clusters(f, part_offset, bpb, fat_entries):
    partial_clusters = set()
    max_chain = bpb["count_of_clusters"] + 2
    clus_bytes = cluster_size_bytes(bpb)
    visited_dirs = set()

    def walk_entries(raw_dir, is_root=False):
        for ent in iter_directory_entries(raw_dir):
            attr = ent[11]
            is_dir = (attr & 0x10) != 0
            is_volume = (attr & 0x08) != 0
            if is_volume:
                continue

            start = entry_start_cluster(ent, bpb["fat_type"])
            size = struct.unpack_from("<I", ent, 28)[0]
            name0 = ent[0]

            if is_dir:
                if name0 == 0x2E:
                    continue
                if start < 2:
                    continue
                if start in visited_dirs:
                    continue
                visited_dirs.add(start)
                subdir = directory_chain_bytes(f, part_offset, bpb, fat_entries, start)
                if subdir:
                    walk_entries(subdir)
                continue

            if start < 2 or size == 0:
                continue

            needed = (size + clus_bytes - 1) // clus_bytes
            if needed <= 0 or (size % clus_bytes) == 0:
                continue

            chain = get_cluster_chain(fat_entries, bpb["fat_type"], start, max_chain)
            if len(chain) >= needed:
                partial_clusters.add(chain[needed - 1])

    if bpb["fat_type"] == "FAT16":
        walk_entries(root_dir_bytes(f, part_offset, bpb), is_root=True)
    else:
        # FAT32 root directory starts at cluster in BPB offset 44.
        root_clus = struct.unpack_from("<I", read_at(f, part_offset, 512), 44)[0]
        if root_clus >= 2:
            visited_dirs.add(root_clus)
            walk_entries(directory_chain_bytes(f, part_offset, bpb, fat_entries, root_clus), is_root=True)

    return partial_clusters


def render_cluster_map(clusters, cols, scale, stats, info):
    if cols <= 0:
        raise ValueError("cols must be > 0")
    if scale <= 0:
        raise ValueError("scale must be > 0")

    total = len(clusters)
    cols = choose_portrait_cols(total, cols)
    rows = max(1, math.ceil(total / cols))

    # Portrait layout with a detailed legend panel above the map.
    pad = 8
    title_h = 14
    legend_h = 54
    map_w = cols
    map_h = rows

    width = (pad * 2 + map_w) * scale
    height = (pad * 2 + title_h + legend_h + map_h) * scale

    # Palette tuned to resemble old disk check maps.
    palette = {
        "bg": (204, 204, 204),
        "free": (10, 60, 48),
        "used": (115, 230, 203),
        "partial": (62, 187, 158),
        "bad": (220, 45, 35),
        "empty": (180, 180, 180),
        "frame": (40, 40, 40),
        "legend_free": (10, 60, 48),
        "legend_used": (115, 230, 203),
        "legend_partial": (62, 187, 158),
        "legend_bad": (220, 45, 35),
        "text": (20, 20, 20),
    }

    pixels = bytearray(width * height * 3)

    def set_px(x, y, rgb):
        if x < 0 or y < 0 or x >= width or y >= height:
            return
        i = (y * width + x) * 3
        pixels[i : i + 3] = bytes(rgb)

    def fill_rect(x0, y0, w, h, rgb):
        for yy in range(y0, y0 + h):
            row = (yy * width) * 3
            for xx in range(x0, x0 + w):
                i = row + xx * 3
                pixels[i : i + 3] = bytes(rgb)

    def draw_char(ch, x, y, px_scale, rgb):
        glyph = FONT_5X7.get(ch, FONT_5X7[" "])
        for gy, row_bits in enumerate(glyph):
            for gx, bit in enumerate(row_bits):
                if bit == "1":
                    fill_rect(x + gx * px_scale, y + gy * px_scale, px_scale, px_scale, rgb)

    def draw_text(text, x, y, px_scale, rgb):
        cursor = x
        for ch in text.upper():
            draw_char(ch, cursor, y, px_scale, rgb)
            cursor += 6 * px_scale

    # Background
    fill_rect(0, 0, width, height, palette["bg"])

    # Map frame and area.
    map_x = pad * scale
    map_y = (pad + title_h + legend_h) * scale
    area_w = map_w * scale
    area_h = map_h * scale

    fill_rect(map_x - scale, map_y - scale, area_w + 2 * scale, area_h + 2 * scale, palette["frame"])
    fill_rect(map_x, map_y, area_w, area_h, palette["empty"])

    # Cluster cells (1 cluster = 1 square of `scale` pixels).
    for idx, state in enumerate(clusters):
        r = idx // cols
        c = idx % cols
        color = palette["free"] if state == "free" else palette["used"]
        if state == "partial":
            color = palette["partial"]
        if state == "bad":
            color = palette["bad"]
        x = map_x + c * scale
        y = map_y + r * scale
        fill_rect(x, y, scale, scale, color)

    text_scale = max(1, scale // 2)
    title_y = (pad + 2) * scale
    draw_text(f"DISK MAP {info['fat_type']}", map_x, title_y, text_scale, palette["text"])

    legend_y = (pad + title_h + 2) * scale
    box = 7 * scale
    line_h = 10 * text_scale

    legend_rows = [
        ("FREE", stats["free"], palette["legend_free"]),
        ("PARTIAL", stats["partial"], palette["legend_partial"]),
        ("USED", stats["used"], palette["legend_used"]),
        ("BAD", stats["bad"], palette["legend_bad"]),
    ]

    total_safe = max(1, stats["total"])
    for i, (name, count, color) in enumerate(legend_rows):
        by = legend_y + i * (box + 2 * scale)
        fill_rect(map_x, by, box, box, color)
        for x in range(map_x, map_x + box):
            set_px(x, by, palette["frame"])
            set_px(x, by + box - 1, palette["frame"])
        for y in range(by, by + box):
            set_px(map_x, y, palette["frame"])
            set_px(map_x + box - 1, y, palette["frame"])

        pct = int((count * 100.0) / total_safe + 0.5)
        line = f"{name}: {count} ({pct}%)"
        draw_text(line, map_x + box + 3 * scale, by + scale, text_scale, palette["text"])

    info_y = legend_y + 4 * (box + 2 * scale) + scale
    draw_text(f"TOTAL: {stats['total']}", map_x, info_y, text_scale, palette["text"])
    draw_text(f"PARTITION: {info['partition']}", map_x, info_y + line_h, text_scale, palette["text"])
    draw_text(f"CLUSTERS/ROW: {cols}", map_x, info_y + line_h * 2, text_scale, palette["text"])

    return width, height, pixels


def detect_fat_partition(f, image_size, partition_choice):
    parts = parse_mbr_partitions(f)

    candidates = []
    for p in parts:
        part_off = p["start_lba"] * SECTOR_SIZE
        if part_off + 512 > image_size:
            continue
        boot = read_at(f, part_off, 512)
        if boot[510:512] != b"\x55\xAA":
            continue
        try:
            bpb = parse_bpb(boot)
        except Exception:
            continue
        if bpb["fat_type"] in ("FAT16", "FAT32"):
            candidates.append((p, bpb))

    if candidates:
        if partition_choice is None:
            return candidates[0][0], candidates[0][1]
        for p, bpb in candidates:
            if p["index"] == partition_choice:
                return p, bpb
        raise ValueError(f"Requested partition index {partition_choice} is not a FAT16/32 partition")

    # Fall back to superfloppy (volume starts at offset 0).
    boot = read_at(f, 0, 512)
    if boot[510:512] != b"\x55\xAA":
        raise ValueError("No FAT partition found and image is not a FAT superfloppy")

    bpb = parse_bpb(boot)
    if bpb["fat_type"] not in ("FAT16", "FAT32"):
        raise ValueError(f"Unsupported FAT type: {bpb['fat_type']}")

    part = {
        "index": -1,
        "type": 0,
        "start_lba": 0,
        "sectors": bpb["tot_sec"],
    }
    return part, bpb


def main():
    ap = argparse.ArgumentParser(description="Generate a disk usage map PNG from a FAT .img image")
    ap.add_argument("--i", required=True, help="Input disk image path (.img)")
    ap.add_argument("--o", required=True, help="Output PNG path")
    ap.add_argument("--partition", type=int, default=None, help="MBR partition index 0..3 (default: first FAT)")
    ap.add_argument(
        "--cols",
        type=int,
        default=None,
        help="Clusters per row in output map (default: auto portrait)",
    )
    ap.add_argument("--scale", type=int, default=4, help="Pixel size for each cluster cell")
    args = ap.parse_args()

    if args.cols is not None and args.cols < 8:
        raise SystemExit("--cols must be >= 8")
    if args.scale < 1:
        raise SystemExit("--scale must be >= 1")

    image_path = args.i
    out_path = args.o

    if not os.path.isfile(image_path):
        raise SystemExit(f"Input file not found: {image_path}")

    image_size = os.path.getsize(image_path)

    with open(image_path, "rb") as f:
        part, bpb = detect_fat_partition(f, image_size, args.partition)

        part_off = part["start_lba"] * SECTOR_SIZE
        fat_entries = load_fat_entries(f, part_off, bpb)
        partial_set = find_partial_file_clusters(f, part_off, bpb, fat_entries)

        clusters, free_count, used_count, bad_count = classify_clusters(
            fat_entries, bpb["fat_type"], bpb["count_of_clusters"]
        )

    partial_count = 0
    for i, state in enumerate(clusters):
        if state != "used":
            continue
        clus_num = i + 2
        if clus_num in partial_set:
            clusters[i] = "partial"
            partial_count += 1

    used_count = max(0, used_count - partial_count)

    stats = {
        "total": len(clusters),
        "free": free_count,
        "used": used_count,
        "partial": partial_count,
        "bad": bad_count,
    }
    info = {
        "fat_type": bpb["fat_type"],
        "partition": part["index"],
    }

    width, height, rgb = render_cluster_map(clusters, args.cols, args.scale, stats, info)
    write_png_rgb(out_path, width, height, rgb)

    total = len(clusters)
    print(f"Input image : {image_path}")
    print(f"FAT type    : {bpb['fat_type']}")
    print(f"Partition   : start LBA {part['start_lba']} (index {part['index']})")
    print(
        f"Clusters    : total={total} free={free_count} used={used_count} "
        f"partial={partial_count} bad={bad_count}"
    )
    print(f"Output PNG  : {out_path} ({width}x{height})")


if __name__ == "__main__":
    main()

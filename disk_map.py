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


def render_cluster_map(clusters, cols, scale):
    if cols <= 0:
        raise ValueError("cols must be > 0")
    if scale <= 0:
        raise ValueError("scale must be > 0")

    total = len(clusters)
    rows = max(1, math.ceil(total / cols))

    # A small frame around the map.
    pad = 8
    legend_h = 22
    map_w = cols
    map_h = rows

    width = (pad * 2 + map_w) * scale
    height = (pad * 2 + legend_h + map_h) * scale

    # Palette tuned to resemble old disk check maps.
    palette = {
        "bg": (204, 204, 204),
        "free": (12, 150, 150),
        "used": (0, 225, 225),
        "bad": (220, 45, 35),
        "empty": (180, 180, 180),
        "frame": (40, 40, 40),
        "legend_free": (12, 150, 150),
        "legend_used": (0, 225, 225),
        "legend_bad": (220, 45, 35),
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

    # Background
    fill_rect(0, 0, width, height, palette["bg"])

    # Map frame and area.
    map_x = pad * scale
    map_y = (pad + legend_h) * scale
    area_w = map_w * scale
    area_h = map_h * scale

    fill_rect(map_x - scale, map_y - scale, area_w + 2 * scale, area_h + 2 * scale, palette["frame"])
    fill_rect(map_x, map_y, area_w, area_h, palette["empty"])

    # Cluster cells (1 cluster = 1 square of `scale` pixels).
    for idx, state in enumerate(clusters):
        r = idx // cols
        c = idx % cols
        color = palette["free"] if state == "free" else palette["used"]
        if state == "bad":
            color = palette["bad"]
        x = map_x + c * scale
        y = map_y + r * scale
        fill_rect(x, y, scale, scale, color)

    # Tiny legend color bars (no text to keep this dependency-free).
    legend_y = (pad + 4) * scale
    box = 6 * scale
    gap = 3 * scale
    lx = map_x
    fill_rect(lx, legend_y, box, box, palette["legend_free"])
    fill_rect(lx + box + gap, legend_y, box, box, palette["legend_used"])
    fill_rect(lx + 2 * (box + gap), legend_y, box, box, palette["legend_bad"])

    # Thin border around legend boxes.
    for k in range(3):
        bx = lx + k * (box + gap)
        by = legend_y
        for x in range(bx, bx + box):
            set_px(x, by, palette["frame"])
            set_px(x, by + box - 1, palette["frame"])
        for y in range(by, by + box):
            set_px(bx, y, palette["frame"])
            set_px(bx + box - 1, y, palette["frame"])

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
    ap.add_argument("--cols", type=int, default=128, help="Clusters per row in output map")
    ap.add_argument("--scale", type=int, default=4, help="Pixel size for each cluster cell")
    args = ap.parse_args()

    if args.cols < 8:
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
        clusters, free_count, used_count, bad_count = classify_clusters(
            fat_entries, bpb["fat_type"], bpb["count_of_clusters"]
        )

    width, height, rgb = render_cluster_map(clusters, args.cols, args.scale)
    write_png_rgb(out_path, width, height, rgb)

    total = len(clusters)
    print(f"Input image : {image_path}")
    print(f"FAT type    : {bpb['fat_type']}")
    print(f"Partition   : start LBA {part['start_lba']} (index {part['index']})")
    print(f"Clusters    : total={total} free={free_count} used={used_count} bad={bad_count}")
    print(f"Output PNG  : {out_path} ({width}x{height})")


if __name__ == "__main__":
    main()

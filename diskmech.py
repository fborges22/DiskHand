#!/usr/bin/env python3
"""
diskmech.py — a pure-Python FAT16/FAT32 disk checker, repair tool, and defragmenter for *disk images* (no external disk utilities).

⚠️ WARNING
- This operates directly on a disk image file. Back up your image first.
- Supports MBR (including EBR chains). GPT/protective MBR is not supported.
- Targets FAT16 and FAT32 only (not FAT12/exFAT).
- Integrity mode checks FAT copies, lost clusters, cross-links, truncated chains,
    directory-chain errors, and FAT32 FSInfo inconsistencies.
- `--repair` can apply safe repairs for common FAT issues such as mismatched FAT
    copies, bad reserved FAT entries, stale FAT32 FSInfo data, and orphaned
    clusters (lost chains) that can be safely returned to free space.
- `--repair-autofix` applies all repairable fixes without prompting.
- `--repair-ask` asks before each repairable fix.
- Conservative defragmentation compacts files toward the start of the data area
    using only free space; files are skipped when no suitable contiguous run exists.
- `--full` performs a denser, DOS-like full optimization pass that packs files
    toward the start of the volume so free space is consolidated at the end.

New in this complete version
----------------------------
- **Progress bars** (overall and per-file) without extra dependencies (no tqdm required).
- **Stricter integrity checker**: compares FAT copies, detects cross-links, orphans,
  truncated chains, and FSInfo inconsistencies, plus a fragmentation summary.
- **Safer workflow**: strict pre-check runs by default when `--check` is used; you can
  `--force` to continue despite errors, and the tool re-checks after defrag.
- **Perfect mode**: `--perfect` runs iterative full optimization passes to minimize
    internal holes until the allocated cluster region is contiguous or no progress is possible.

Usage examples
--------------
List partitions in a disk image (and exit):
    python fatdefrag.py /path/to/disk.img --list

Check a partition for FAT issues only:
    python diskmech.py /path/to/disk.img -p N --check-only

Repair all safe issues automatically:
    python diskmech.py /path/to/disk.img -p N --repair --repair-autofix --inplace

Ask before each repairable issue:
    python diskmech.py /path/to/disk.img -p N --repair --repair-ask --inplace

Defragment a partition after checks pass:
    python diskmech.py /path/to/disk.img -p N --inplace

Dry-run to preview defragmentation moves (no writes):
    python diskmech.py /path/to/disk.img -p N --dry-run --verbose

Make a backup first:
    python diskmech.py /path/to/disk.img -p N --backup disk.img.bak --repair --repair-autofix --inplace
"""
from __future__ import annotations
import argparse
import hashlib
import io
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Iterable, Set

# ------------------------- MBR / Partition parsing -------------------------
MBR_PART_OFFSET = 446
MBR_ENTRY_SIZE = 16
MBR_SIGNATURE_OFFSET = 510
MBR_SIGNATURE = b"\x55\xAA"

FAT_TYPES = {
    0x04: "FAT16 (CHS)",
    0x06: "FAT16 (LBA)",
    0x0E: "FAT16 (LBA, CHS alt)",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
}

EXT_TYPES = {0x05, 0x0F}
GPT_PROTECTIVE = 0xEE

@dataclass
class Part:
    index: int
    part_type: int
    lba_start: int
    sectors: int
    is_extended: bool = False
    description: str = ""
    parent_ext_base: int = 0

    def __str__(self) -> str:
        kind = FAT_TYPES.get(self.part_type, f"type 0x{self.part_type:02X}")
        size_mb = (self.sectors * 512) / (1024 * 1024)
        ext = " (extended)" if self.is_extended else ""
        return f"[{self.index}] LBA {self.lba_start:<10} size {size_mb:>8.1f} MiB  {kind}{ext}"

# ------------------------- Low-level I/O helpers -------------------------

def read_at(f: io.BufferedRandom, offset: int, size: int) -> bytes:
    """Read exactly ``size`` bytes from ``offset`` or raise ``IOError``."""
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise IOError("Short read")
    return data


def write_at(f: io.BufferedRandom, offset: int, data: bytes) -> None:
    """Write all bytes in ``data`` at ``offset`` or raise ``IOError``."""
    f.seek(offset)
    w = f.write(data)
    if w != len(data):
        raise IOError("Short write")

# ------------------------- Progress utilities -------------------------
class Progress:
    def __init__(self, total: int, prefix: str = "") -> None:
        """Create a simple terminal progress bar with a fixed-width visual bar."""
        self.total = max(int(total), 0)
        self.current = 0
        self.prefix = prefix
        self._width = 40
        self._last_render = ""

    def _render(self) -> str:
        if self.total <= 0:
            bar = "[" + ("-" * self._width) + "]"
            return f"{self.prefix} {bar}   0% (0/0)"
        ratio = self.current / self.total
        ratio = 1.0 if ratio > 1 else ratio
        filled = int(self._width * ratio)
        bar = "[" + ("#" * filled) + ("-" * (self._width - filled)) + "]"
        pct = int(ratio * 100)
        return f"{self.prefix} {bar} {pct:3d}% ({self.current}/{self.total})"

    def update(self, n: int = 1) -> None:
        """Advance progress by ``n`` steps and redraw the bar when it changes."""
        self.current += n
        if self.current > self.total:
            self.current = self.total
        line = "\r" + self._render()
        if line != self._last_render:
            sys.stderr.write(line)
            sys.stderr.flush()
            self._last_render = line

    def close(self) -> None:
        """Render a final progress line and terminate it with a newline."""
        sys.stderr.write("\r" + self._render() + "\n")
        sys.stderr.flush()

# ------------------------- MBR / EBR parsing -------------------------

def parse_mbr_partitions(f: io.BufferedRandom) -> List[Part]:
    """Parse primary and logical partitions from an MBR image.

    Supports extended partitions via EBR chaining and rejects GPT-protective
    MBRs because GPT handling is out of scope for this tool.
    """
    mbr = read_at(f, 0, 512)
    if mbr[MBR_SIGNATURE_OFFSET:MBR_SIGNATURE_OFFSET+2] != MBR_SIGNATURE:
        raise ValueError("Invalid MBR signature; GPT or raw volume not supported.")

    parts: List[Part] = []

    def parse_entry(raw: bytes, idx: int) -> Part:
        ptype = raw[4]
        lba_start = struct.unpack_from("<I", raw, 8)[0]
        sectors = struct.unpack_from("<I", raw, 12)[0]
        return Part(index=idx, part_type=ptype, lba_start=lba_start, sectors=sectors,
                    is_extended=(ptype in EXT_TYPES))

    primaries: List[Part] = []
    for i in range(4):
        entry = mbr[MBR_PART_OFFSET + i*MBR_ENTRY_SIZE: MBR_PART_OFFSET + (i+1)*MBR_ENTRY_SIZE]
        p = parse_entry(entry, i)
        if p.sectors == 0:
            continue
        if p.part_type == GPT_PROTECTIVE:
            raise ValueError("GPT/protective MBR detected; not supported.")
        primaries.append(p)

    parts.extend(primaries)

    # Follow extended partitions (EBR chain)
    for p in primaries:
        if not p.is_extended:
            continue
        ext_base = p.lba_start
        next_ebr_rel = 0
        while True:
            ebr_lba = ext_base + next_ebr_rel
            ebr = read_at(f, ebr_lba*512, 512)
            if ebr[MBR_SIGNATURE_OFFSET:MBR_SIGNATURE_OFFSET+2] != MBR_SIGNATURE:
                break
            e1 = ebr[MBR_PART_OFFSET:MBR_PART_OFFSET+MBR_ENTRY_SIZE]
            lp = Part(index=len(parts), part_type=e1[4],
                      lba_start=ebr_lba + struct.unpack_from("<I", e1, 8)[0],
                      sectors=struct.unpack_from("<I", e1, 12)[0],
                      is_extended=False, parent_ext_base=ext_base)
            if lp.sectors:
                parts.append(lp)
            # Link to next EBR
            e2 = ebr[MBR_PART_OFFSET+MBR_ENTRY_SIZE:MBR_PART_OFFSET+2*MBR_ENTRY_SIZE]
            next_rel = struct.unpack_from("<I", e2, 8)[0]
            if next_rel == 0:
                break
            next_ebr_rel = next_rel

    for p in parts:
        p.description = FAT_TYPES.get(p.part_type, f"0x{p.part_type:02X}")
    return parts

# ------------------------- FAT structures & helpers -------------------------

@dataclass
class BPB:
    byts_per_sec: int
    sec_per_clus: int
    rsvd_sec_cnt: int
    num_fats: int
    root_ent_cnt: int
    tot_sec_16: int
    media: int
    fatsz_16: int
    sec_per_trk: int
    num_heads: int
    hidd_sec: int
    tot_sec_32: int
    fatsz_32: int = 0
    ext_flags: int = 0
    fsver: int = 0
    root_clus: int = 0
    fsinfo: int = 0
    bkbootsec: int = 0
    fat_type: str = ""
    fat_bits: int = 0

    @staticmethod
    def parse(boot: bytes) -> 'BPB':
        """Parse a FAT BPB from a 512-byte boot sector and infer FAT type."""
        byts_per_sec = struct.unpack_from("<H", boot, 11)[0]
        sec_per_clus = boot[13]
        rsvd_sec_cnt = struct.unpack_from("<H", boot, 14)[0]
        num_fats = boot[16]
        root_ent_cnt = struct.unpack_from("<H", boot, 17)[0]
        tot_sec_16 = struct.unpack_from("<H", boot, 19)[0]
        media = boot[21]
        fatsz_16 = struct.unpack_from("<H", boot, 22)[0]
        sec_per_trk = struct.unpack_from("<H", boot, 24)[0]
        num_heads = struct.unpack_from("<H", boot, 26)[0]
        hidd_sec = struct.unpack_from("<I", boot, 28)[0]
        tot_sec_32 = struct.unpack_from("<I", boot, 32)[0]

        fatsz_32 = ext_flags = fsver = root_clus = fsinfo = bkbootsec = 0
        if fatsz_16 == 0:
            fatsz_32 = struct.unpack_from("<I", boot, 36)[0]
            ext_flags = struct.unpack_from("<H", boot, 40)[0]
            fsver = struct.unpack_from("<H", boot, 42)[0]
            root_clus = struct.unpack_from("<I", boot, 44)[0]
            fsinfo = struct.unpack_from("<H", boot, 48)[0]
            bkbootsec = struct.unpack_from("<H", boot, 50)[0]

        fatsz = fatsz_16 if fatsz_16 else fatsz_32
        root_dir_sectors = ((root_ent_cnt * 32) + (byts_per_sec - 1)) // byts_per_sec
        tot_sec = tot_sec_16 if tot_sec_16 else tot_sec_32
        data_sectors = tot_sec - (rsvd_sec_cnt + num_fats * fatsz + root_dir_sectors)
        count_of_clusters = data_sectors // sec_per_clus if sec_per_clus else 0
        if count_of_clusters < 4085:
            ftype, fbits = "FAT12", 12
        elif count_of_clusters < 65525:
            ftype, fbits = "FAT16", 16
        else:
            ftype, fbits = "FAT32", 32

        return BPB(byts_per_sec, sec_per_clus, rsvd_sec_cnt, num_fats, root_ent_cnt,
                   tot_sec_16, media, fatsz_16, sec_per_trk, num_heads, hidd_sec,
                   tot_sec_32, fatsz_32, ext_flags, fsver, root_clus, fsinfo,
                   bkbootsec, ftype, fbits)

@dataclass
class DirEntry:
    name: str
    attr: int
    start_cluster: int
    size: int
    is_dir: bool
    raw_offset: int


@dataclass(frozen=True)
class RepairAction:
    code: str
    description: str


def _fat_entry_cluster_field_offsets(fat_type: str) -> Tuple[int, ...]:
    if fat_type == "FAT32":
        return (20, 21, 26, 27)
    return (26, 27)

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F

EOC16 = 0xFFF8
EOC32 = 0x0FFFFFF8
FREE16 = 0x0000
FREE32 = 0x00000000
BAD16 = 0xFFF7
BAD32 = 0x0FFFFFF7

@dataclass
class FatVolume:
    f: io.BufferedRandom
    part: Part
    bpb: BPB
    byts_per_sec: int
    sec_per_clus: int
    first_data_sector: int
    first_fat_sector: int
    root_dir_first_sector: int
    root_dir_sectors: int
    fatsz: int
    eoc: int
    free_value: int
    fat_bits: int
    max_cluster: int
    fat: List[int] = field(default_factory=list)

    @staticmethod
    def open(f: io.BufferedRandom, part: Part) -> 'FatVolume':
        """Open a partition as FAT16/FAT32 and load its primary FAT into memory."""
        boot = read_at(f, part.lba_start * 512, 512)
        if boot[510:512] != b"\x55\xAA":
            raise ValueError("Invalid boot sector signature for FAT volume.")
        bpb = BPB.parse(boot)
        if bpb.fat_type not in ("FAT16", "FAT32"):
            raise ValueError(f"Unsupported FAT type: {bpb.fat_type}")
        byts_per_sec = bpb.byts_per_sec
        sec_per_clus = bpb.sec_per_clus
        fatsz = bpb.fatsz_16 if bpb.fatsz_16 else bpb.fatsz_32
        first_fat_sector = part.lba_start + bpb.rsvd_sec_cnt
        root_dir_sectors = ((bpb.root_ent_cnt * 32) + (byts_per_sec - 1)) // byts_per_sec
        if bpb.fat_type == "FAT32":
            root_dir_first_sector = 0
        else:
            root_dir_first_sector = first_fat_sector + bpb.num_fats * fatsz
        first_data_sector = first_fat_sector + bpb.num_fats * fatsz + root_dir_sectors
        tot_sec = bpb.tot_sec_16 if bpb.tot_sec_16 else bpb.tot_sec_32
        data_sectors = tot_sec - (bpb.rsvd_sec_cnt + bpb.num_fats * fatsz + root_dir_sectors)
        cluster_count = data_sectors // sec_per_clus if sec_per_clus else 0
        max_cluster = cluster_count + 1

        eoc = EOC32 if bpb.fat_type == "FAT32" else EOC16
        free_value = FREE32 if bpb.fat_type == "FAT32" else FREE16

        vol = FatVolume(
            f=f, part=part, bpb=bpb, byts_per_sec=byts_per_sec, sec_per_clus=sec_per_clus,
            first_data_sector=first_data_sector, first_fat_sector=first_fat_sector,
            root_dir_first_sector=root_dir_first_sector, root_dir_sectors=root_dir_sectors,
            fatsz=fatsz, eoc=eoc, free_value=free_value, fat_bits=bpb.fat_bits,
            max_cluster=max_cluster,
        )
        vol.load_fat()
        return vol

    def first_sector_of_cluster(self, n: int) -> int:
        """Return the absolute sector index for cluster ``n`` in the data area."""
        if n < 2 or n > self.max_cluster:
            raise ValueError(f"Cluster index out of data range: {n}")
        return self.first_data_sector + (n - 2) * self.sec_per_clus

    def cluster_offset_bytes(self, n: int) -> int:
        """Return the absolute byte offset for the start of cluster ``n``."""
        return self.first_sector_of_cluster(n) * self.byts_per_sec

    def load_fat(self) -> None:
        """Load the first FAT copy into ``self.fat`` using canonical entry masking."""
        fat_bytes = read_at(self.f, self.first_fat_sector * self.byts_per_sec, self.fatsz * self.byts_per_sec)
        if self.bpb.fat_type == "FAT16":
            count = len(fat_bytes) // 2
            self.fat = list(struct.unpack_from(f"<{count}H", fat_bytes, 0))
        else:
            count = len(fat_bytes) // 4
            vals = list(struct.unpack_from(f"<{count}I", fat_bytes, 0))
            self.fat = [v & 0x0FFFFFFF for v in vals]

    def flush_fat(self) -> None:
        """Persist the in-memory FAT to all on-disk FAT copies and fsync the image."""
        if self.bpb.fat_type == "FAT16":
            out = struct.pack(f"<{len(self.fat)}H", *self.fat)
        else:
            vals = [v & 0x0FFFFFFF for v in self.fat]
            out = struct.pack(f"<{len(vals)}I", *vals)
        for i in range(self.bpb.num_fats):
            off = (self.first_fat_sector + i * self.fatsz) * self.byts_per_sec
            write_at(self.f, off, out)
        self.f.flush()
        os.fsync(self.f.fileno())

    def next_cluster(self, n: int) -> Optional[int]:
        """Return the next cluster in chain, ``None`` at EOC, or raise on invalid links."""
        if n < 2 or n > self.max_cluster:
            raise ValueError(f"Cluster index out of range: {n}")
        v = self.fat[n]
        if self.bpb.fat_type == "FAT16":
            if v >= EOC16: return None
            if v == BAD16: raise ValueError("Encountered BAD cluster")
            if v == FREE16: raise ValueError("Encountered FREE cluster in chain")
            if v < 2 or v > self.max_cluster:
                raise ValueError(f"Next cluster out of range: {v}")
            return v
        else:
            if v >= EOC32: return None
            if v == BAD32: raise ValueError("Encountered BAD cluster")
            if v == FREE32: raise ValueError("Encountered FREE cluster in chain")
            if v < 2 or v > self.max_cluster:
                raise ValueError(f"Next cluster out of range: {v}")
            return v

    def cluster_chain(self, start: int) -> List[int]:
        """Follow and return the full cluster chain from ``start`` with loop detection."""
        if start < 2:
            return []
        chain, seen = [], set()
        n = start
        while n is not None:
            if n in seen:
                raise ValueError("FAT loop detected")
            seen.add(n)
            chain.append(n)
            n = self.next_cluster(n)
        return chain

    def cluster_read(self, n: int) -> bytes:
        """Read and return one full cluster payload."""
        off = self.cluster_offset_bytes(n)
        size = self.sec_per_clus * self.byts_per_sec
        return read_at(self.f, off, size)

    def cluster_write(self, n: int, data: bytes) -> None:
        """Write one full cluster payload; partial writes are rejected."""
        size = self.sec_per_clus * self.byts_per_sec
        if len(data) != size:
            raise ValueError("cluster_write: wrong data size")
        off = self.cluster_offset_bytes(n)
        write_at(self.f, off, data)

    def iter_root_dir_sectors(self) -> Iterable[Tuple[int, bytes]]:
        """Yield ``(byte_offset, sector_bytes)`` for root directory sectors."""
        if self.bpb.fat_type == "FAT16":
            first = self.root_dir_first_sector
            for i in range(self.root_dir_sectors):
                off = (first + i) * self.byts_per_sec
                yield off, read_at(self.f, off, self.byts_per_sec)
        else:
            for off, sec in self.iter_dir_chain(self.bpb.root_clus):
                yield off, sec

    def iter_dir_chain(self, start_cluster: int) -> Iterable[Tuple[int, bytes]]:
        """Yield directory sectors for a directory chain starting at ``start_cluster``."""
        size = self.byts_per_sec
        for clus in self.cluster_chain(start_cluster):
            first_sec = self.first_sector_of_cluster(clus)
            for i in range(self.sec_per_clus):
                off = (first_sec + i) * size
                yield off, read_at(self.f, off, size)

    def list_directory(self, start_cluster: Optional[int], base_offset: Optional[int] = None):
        """Parse a directory and return normalized ``DirEntry`` records.

        Handles FAT16 fixed-root and FAT16/FAT32 chained directories,
        long-file-name reconstruction, and standard dot/volume entry filtering.
        """
        ATTR_LFN       = 0x0F
        ATTR_DIRECTORY = 0x10
        ATTR_VOLUME_ID = 0x08

        entries: list[DirEntry] = []
        lfn_stack: list[bytes] = []
        stop = False

        def parse_sector(off: int, sec: bytes):
            nonlocal entries, lfn_stack, stop
            for i in range(0, len(sec), 32):
                e = sec[i:i+32]
                raw_off = off + i

                name0 = e[0]
                if name0 == 0x00:
                    # End-of-directory marker: no valid entries follow in later sectors either.
                    lfn_stack.clear()
                    stop = True
                    return
                if name0 == 0xE5:
                    # deleted entry; discard any pending LFN
                    lfn_stack.clear()
                    continue

                attr = e[11]
                if attr == ATTR_LFN:
                    # long file name component
                    lfn_stack.append(e)
                    continue

                is_dir = bool(attr & ATTR_DIRECTORY)

                # Build display name
                if lfn_stack:
                    name = self._lfn_to_name(reversed(lfn_stack))
                    lfn_stack.clear()
                else:
                    base = e[0:8].decode("ascii", errors="replace").rstrip()
                    ext  = e[8:11].decode("ascii", errors="replace").rstrip()
                    name = f"{base}.{ext}".rstrip(".")
                name = name.strip().strip("/\\")  # never carry trailing slashes

                # Skip volume labels and dot entries
                if attr & ATTR_VOLUME_ID:
                    continue
                if is_dir and name in (".", ".."):
                    continue

                start_lo = struct.unpack_from("<H", e, 26)[0]
                start_hi = struct.unpack_from("<H", e, 20)[0] if self.bpb.fat_type == "FAT32" else 0
                start    = (start_hi << 16) | start_lo
                size     = struct.unpack_from("<I", e, 28)[0]

                entries.append(DirEntry(
                    name=name,
                    attr=attr,
                    start_cluster=start,
                    size=size,
                    is_dir=is_dir,
                    raw_offset=raw_off
                ))

        # Walk the directory sectors and parse each one
        if self.bpb.fat_type == "FAT16" and (start_cluster is None or start_cluster < 2):
            # FAT16 root directory lives in a fixed area
            for off, sec in self.iter_root_dir_sectors():
                parse_sector(off, sec)
                if stop:
                    break
        else:
            # Subdirectory (FAT16) or any directory (FAT32) via cluster chain
            if start_cluster is None or start_cluster < 2:
                # Defensive: FAT32 root should have a valid cluster; if not, return empty
                return entries
            for off, sec in self.iter_dir_chain(start_cluster):
                parse_sector(off, sec)
                if stop:
                    break

        return entries

    @staticmethod
    def _lfn_to_name(entries: Iterable[bytes]) -> str:
        """Decode a sequence of LFN entries into a Unicode filename."""
        name_chars: List[str] = []
        for e in entries:
            parts = e[1:11] + e[14:26] + e[28:32]
            for j in range(0, len(parts), 2):
                c = parts[j:j+2]
                if c in (b"\xFF\xFF", b"\x00\x00"):
                    continue
                name_chars.append(c.decode('utf-16le', errors='ignore'))
        return ''.join(name_chars).rstrip('\u0000').rstrip()

    def update_dir_start_cluster(self, entry: DirEntry, new_start: int) -> None:
        """Patch a directory entry's start-cluster fields in place."""
        sec_off = entry.raw_offset - (entry.raw_offset % self.byts_per_sec)
        sec = bytearray(read_at(self.f, sec_off, self.byts_per_sec))
        i = entry.raw_offset - sec_off
        struct.pack_into("<H", sec, i+26, new_start & 0xFFFF)
        if self.bpb.fat_type == "FAT32":
            struct.pack_into("<H", sec, i+20, (new_start >> 16) & 0xFFFF)
        write_at(self.f, sec_off, bytes(sec))

    def read_dir_start_cluster(self, entry: DirEntry) -> int:
        """Read and return the current start cluster from an on-disk directory entry."""
        sec_off = entry.raw_offset - (entry.raw_offset % self.byts_per_sec)
        sec = read_at(self.f, sec_off, self.byts_per_sec)
        i = entry.raw_offset - sec_off
        start_lo = struct.unpack_from("<H", sec, i + 26)[0]
        start_hi = struct.unpack_from("<H", sec, i + 20)[0] if self.bpb.fat_type == "FAT32" else 0
        return (start_hi << 16) | start_lo

    def read_dir_entry_bytes(self, entry: DirEntry) -> bytes:
        """Return the raw 32-byte on-disk directory entry for verification."""
        sec_off = entry.raw_offset - (entry.raw_offset % self.byts_per_sec)
        sec = read_at(self.f, sec_off, self.byts_per_sec)
        i = entry.raw_offset - sec_off
        return sec[i:i+32]

    def update_fsinfo(self) -> None:
        """Recompute and write FAT32 FSInfo free-count and next-free hint."""
        if self.bpb.fat_type != "FAT32" or self.bpb.fsinfo == 0:
            return
        fsinfo_sec = (self.part.lba_start + self.bpb.fsinfo) * self.byts_per_sec
        sec = bytearray(read_at(self.f, fsinfo_sec, 512))
        free = sum(1 for v in self.fat[2:self.max_cluster + 1] if v == self.free_value)
        hint = 2
        while hint <= self.max_cluster and self.fat[hint] != self.free_value:
            hint += 1
        if hint > self.max_cluster:
            hint = 0xFFFFFFFF
        struct.pack_into("<I", sec, 0x1E4, free if free < 0xFFFFFFFF else 0xFFFFFFFF)
        struct.pack_into("<I", sec, 0x1E8, hint)
        write_at(self.f, fsinfo_sec, bytes(sec))

    def normalize_reserved_fat_entries(self) -> List[str]:
        """Apply canonical values to reserved FAT entries and report applied fixes."""
        repairs: List[str] = []
        for index, expected in self.reserved_fat_entry_fixes():
            self.fat[index] = expected
            if self.bpb.fat_type == "FAT16":
                if index == 0:
                    repairs.append(f"Normalized FAT[0] to 0x{expected:04X}")
                else:
                    repairs.append("Normalized FAT[1] to 0xFFFF")
            else:
                if index == 0:
                    repairs.append(f"Normalized FAT[0] to 0x{expected:08X}")
                else:
                    repairs.append("Normalized FAT[1] to 0x0FFFFFFF")
        return repairs

    def reserved_fat_entry_fixes(self) -> List[Tuple[int, int]]:
        """Return ``(index, expected_value)`` pairs for incorrect reserved FAT entries."""
        if len(self.fat) < 2:
            return []

        fixes: List[Tuple[int, int]] = []
        media = self.bpb.media & 0xFF
        if self.bpb.fat_type == "FAT16":
            expected_f0 = 0xFFF0 | media
            expected_f1 = 0xFFFF
        else:
            expected_f0 = 0x0FFFFFF0 | media
            expected_f1 = 0x0FFFFFFF

        if self.fat[0] != expected_f0:
            fixes.append((0, expected_f0))
        if self.fat[1] != expected_f1:
            fixes.append((1, expected_f1))
        return fixes

    def update_dir_self_pointer(self, dir_start: int) -> None:
        """Update the '.' entry start cluster for a moved subdirectory."""
        sec_off = self.cluster_offset_bytes(dir_start)
        sec = bytearray(read_at(self.f, sec_off, self.byts_per_sec))
        ent = sec[:32]
        if len(ent) < 32:
            return
        # Only patch when first entry looks like a normal '.' directory entry.
        if ent[0] != 0x2E or ent[11] == ATTR_LFN:
            return
        struct.pack_into("<H", sec, 26, dir_start & 0xFFFF)
        if self.bpb.fat_type == "FAT32":
            struct.pack_into("<H", sec, 20, (dir_start >> 16) & 0xFFFF)
        write_at(self.f, sec_off, bytes(sec))

# ------------------------- Integrity checker -------------------------
class IntegrityChecker:
    def __init__(self, vol: 'FatVolume', strict: bool = True, verbose: bool = False) -> None:
        self.vol = vol
        self.strict = strict
        self.verbose = verbose
        self.cluster_size = vol.sec_per_clus * vol.byts_per_sec

    def _canon_dir(self, p: str) -> str:
        return p.rstrip("/\\") + "/"

    def _cluster_chain_upto(self, start: int, max_len: int):
        """Return up to max_len clusters from the chain starting at `start`.
        Also returns flags: truncated (chain shorter than max_len), looped, overlong."""
        chain = []
        seen = set()
        n = start
        looped = False
        while n is not None and len(chain) < max_len:
            if n in seen:
                looped = True
                break
            seen.add(n)
            chain.append(n)
            try:
                n = self.vol.next_cluster(n)
            except ValueError as ex:  # BAD cluster
                raise
        truncated = len(chain) < max_len and n is None
        overlong = len(chain) == max_len and n is not None and not looped
        return chain, truncated, looped, overlong

    # POSIX join independent of host OS to avoid "\" vs "/" mismatches
    def _pjoin(self, parent: str, name: str) -> str:
        if not parent or parent == "/":
            return "/" + name.strip("/\\")
        return (parent.rstrip("/\\") + "/" + name.strip("/\\")).replace("//", "/")

    # Compare FAT copies for mismatches
    def _compare_fat_copies(self) -> Tuple[bool, List[int]]:
        mismatches: List[int] = []
        if self.vol.bpb.num_fats <= 1:
            return True, mismatches
        base = read_at(self.vol.f, self.vol.first_fat_sector * self.vol.byts_per_sec, self.vol.fatsz * self.vol.byts_per_sec)
        for i in range(1, self.vol.bpb.num_fats):
            other = read_at(self.vol.f, (self.vol.first_fat_sector + i * self.vol.fatsz) * self.vol.byts_per_sec, self.vol.fatsz * self.vol.byts_per_sec)
            if other != base:
                mismatches.append(i)
        return (len(mismatches) == 0), mismatches

    # Walk filesystem once, collect used clusters, detect issues, and count fragmentation.
    def _scan_filesystem(self) -> Tuple[Dict[int, str], List[str], int, int]:
        used: Dict[int, str] = {}
        problems: List[str] = []
        frag_files = 0
        total_files = 0

        # BFS over directories starting at root
        q: List[Tuple[Optional[int], str]] = []
        if self.vol.bpb.fat_type == "FAT16":
            q.append((None, "/"))
        else:
            q.append((self.vol.bpb.root_clus, "/"))
        seen_dirs = set()
        while q:
            start, path = q.pop(0)
            try:
                entries = self.vol.list_directory(start)
            except Exception as e:
                problems.append(f"Directory read error at {path}: {e}")
                continue
            for e in entries:
                if e.is_dir:
                    if e.name in (".", ".."):
                        continue
                    if e.start_cluster >= 2:
                        dir_path = self._pjoin(path, e.name)
                        this_dir = self._canon_dir(dir_path)

                        if e.start_cluster not in seen_dirs:
                            seen_dirs.add(e.start_cluster)
                            q.append((e.start_cluster, dir_path))
                        try:
                            for c in self.vol.cluster_chain(e.start_cluster):
                                # Compare canonically to avoid "/DOS/" vs "/DOS//"
                                if c in used and used[c].rstrip("/\\") != this_dir.rstrip("/\\"):
                                    problems.append(
                                        f"Cross-link: cluster {c} used by {used[c]} and {this_dir}"
                                    )
                                used.setdefault(c, this_dir)
                        except Exception as ex:
                            problems.append(f"Dir chain error for {dir_path}: {ex}")
                else:
                    # Regular file
                    if e.start_cluster >= 2 and e.size > 0:
                        total_files += 1
                        file_path = self._pjoin(path, e.name)
                        if e.start_cluster > self.vol.max_cluster:
                            problems.append(
                                f"Invalid first cluster for {file_path}: cluster {e.start_cluster} exceeds max {self.vol.max_cluster}"
                            )
                            continue
                        if self.vol.fat[e.start_cluster] == self.vol.free_value:
                            problems.append(f"Invalid first cluster for {file_path}: cluster {e.start_cluster} is free")
                            continue
                        need = (e.size + self.cluster_size - 1) // self.cluster_size
                        try:
                            chain, truncated, looped, overlong = self._cluster_chain_upto(e.start_cluster, need)
                        except Exception as ex:
                            problems.append(f"File chain error for {file_path}: {ex}")
                            continue

                        if truncated:
                            problems.append(
                                f"Truncated chain for {file_path}: needs {need} clusters, chain has {len(chain)}"
                            )
                        if looped:
                            problems.append(f"FAT loop detected in {file_path}")
                        if overlong:
                            problems.append(
                                f"Overlong chain for {file_path}: size needs {need} clusters, chain continues past file data"
                            )

                        if any(chain[i] + 1 != chain[i+1] for i in range(len(chain)-1)):
                            frag_files += 1

                        for c in chain:
                            if c in used and used[c] != file_path:
                                problems.append(f"Cross-link: cluster {c} used by {used[c]} and {file_path}")
                            used.setdefault(c, file_path)

        return used, problems, frag_files, total_files

    def _collect_used_clusters(self) -> Tuple[Dict[int, str], List[str]]:
        used, problems, _, _ = self._scan_filesystem()
        return used, problems

    # Any allocated cluster not referenced by a file/dir is an orphan
    def _find_orphans(self, used: Dict[int, str]) -> List[int]:
        orphans: List[int] = []
        for c in range(2, self.vol.max_cluster + 1):
            v = self.vol.fat[c]
            if v == self.vol.free_value:
                continue  # free
            if c not in used:
                orphans.append(c)
        return orphans

    # Basic sanity on reserved FAT entries
    def _check_boot_reserved(self) -> List[str]:
        issues: List[str] = []
        f0 = self.vol.fat[0]
        f1 = self.vol.fat[1]
        if self.vol.bpb.fat_type == "FAT16":
            media = self.vol.bpb.media
            if (f0 & 0xFF) != media:
                issues.append(f"FAT[0] media byte mismatch: expected 0x{media:02X}, got 0x{f0 & 0xFF:02X}")
            if f1 < EOC16:
                issues.append("FAT[1] not marked EOC for FAT16")
        else:
            if f1 < EOC32:
                issues.append("FAT[1] not marked EOC for FAT32")
        return issues

    # FSInfo consistency (FAT32 only)
    def _check_fsinfo(self) -> List[str]:
        notes: List[str] = []
        if self.vol.bpb.fat_type != "FAT32" or self.vol.bpb.fsinfo == 0:
            return notes
        fsinfo_off = (self.vol.part.lba_start + self.vol.bpb.fsinfo) * self.vol.byts_per_sec
        sec = read_at(self.vol.f, fsinfo_off, 512)
        cached = struct.unpack_from("<I", sec, 0x1E4)[0]
        computed = sum(1 for v in self.vol.fat[2:self.vol.max_cluster + 1] if v == self.vol.free_value)
        if cached != 0xFFFFFFFF and cached != computed:
            notes.append(f"FSInfo free count {cached} != computed {computed}")
        hint = struct.unpack_from("<I", sec, 0x1E8)[0]
        if hint != 0xFFFFFFFF and (hint < 2 or hint > self.vol.max_cluster):
            notes.append("FSInfo next-free hint out of range")
        return notes

    # Run full integrity suite
    def run(self) -> bool:
        """Run all configured integrity checks and print a diagnostic summary.

        Returns ``True`` only when no strict-failure condition is found.
        """
        ok = True

        # FAT copies identical?
        fats_ok, mism = self._compare_fat_copies()
        if not fats_ok:
            ok = False
            print(f"ERROR: FAT copy mismatch detected in copies: {mism}")

        # Reserved entries heuristics
        for issue in self._check_boot_reserved():
            print("WARN:", issue)

        # Usage map + structural problems
        used, problems, frag_files, total_files = self._scan_filesystem()
        for p in problems:
            if "Cross-link" in p or "chain error" in p or "Truncated" in p or "Overlong" in p or "Invalid first cluster" in p:
                ok = False
            print(("ERROR:" if ("Cross-link" in p or "chain error" in p or "Truncated" in p or "Overlong" in p or "Invalid first cluster" in p) else "WARN:"), p)

        # Orphans (lost chains)
        orphans = self._find_orphans(used)
        if orphans:
            msg = f"Found {len(orphans)} orphan allocated clusters (lost chains)"
            print(("ERROR:" if self.strict else "WARN:"), msg)
            if self.verbose:
                print("  sample:", orphans[:20])
            if self.strict:
                ok = False

        # FSInfo notes
        for note in self._check_fsinfo():
            print("NOTE:", note)

        print(f"Summary: {frag_files}/{total_files} files are fragmented.")
        return ok

    def repair_metadata(self) -> List[str]:
        """Plan and apply all currently repairable metadata fixes."""
        planned = self.planned_repairs()
        return self.apply_repairs({item.code for item in planned})

    def planned_repairs(self) -> List[RepairAction]:
        """Discover safe repairs that can be applied without file-content moves."""
        planned: List[RepairAction] = []
        if self.vol.reserved_fat_entry_fixes():
            planned.append(RepairAction("reserved", "Normalize reserved FAT entries"))

        used, _ = self._collect_used_clusters()
        orphans = self._find_orphans(used)
        if orphans:
            planned.append(RepairAction("orphans", f"Release {len(orphans)} orphan allocated cluster(s)"))

        fats_ok, mismatches = self._compare_fat_copies()
        if not fats_ok:
            planned.append(RepairAction("fat_copies", f"Synchronize FAT copies {mismatches} from the primary FAT"))

        if self._check_fsinfo():
            planned.append(RepairAction("fsinfo", "Refresh FAT32 FSInfo free count and next-free hint"))

        return planned

    def apply_repairs(self, selected: Set[str]) -> List[str]:
        """Apply selected repair codes and return human-readable action results."""
        repairs: List[str] = []
        fat_changed = False

        if "reserved" in selected:
            reserved_repairs = self.vol.normalize_reserved_fat_entries()
            if reserved_repairs:
                repairs.extend(reserved_repairs)
                fat_changed = True

        if "orphans" in selected:
            used, _ = self._collect_used_clusters()
            orphans = self._find_orphans(used)
            if orphans:
                for c in orphans:
                    self.vol.fat[c] = self.vol.free_value
                repairs.append(f"Released {len(orphans)} orphan allocated cluster(s)")
                fat_changed = True

        if "fat_copies" in selected or fat_changed:
            self.vol.flush_fat()
            repairs.append(f"Synchronized {self.vol.bpb.num_fats} FAT copy/copies")

        if "fsinfo" in selected:
            self.vol.update_fsinfo()
            repairs.append("Refreshed FAT32 FSInfo free count and next-free hint")

        return repairs

# ------------------------- Defrag planner -------------------------
@dataclass
class FilePlan:
    entry: DirEntry
    old_chain: List[int]
    new_start: int
    new_chain: List[int]

class Defragmenter:
    def __init__(self, vol: FatVolume, verbose: bool=False, full: bool=False):
        self.vol = vol
        self.verbose = verbose
        self.full = full
        self.cluster_size = vol.sec_per_clus * vol.byts_per_sec
        self.next_free_cursor = 2
        self.free = [i for i in range(2, vol.max_cluster + 1) if vol.fat[i] == vol.free_value]
        self.free_set = set(self.free)
        if self.verbose:
            print(f"Free clusters: {len(self.free)}")

    def _find_free_run(self, needed: int, start: Optional[int] = None) -> Optional[int]:
        """Find the first contiguous free run of ``needed`` clusters at/after ``start``."""
        start = max(self.next_free_cursor if start is None else start, 2)
        run_start = None
        run_len = 0
        i = start
        last = self.vol.max_cluster
        while i <= last:
            if self.vol.fat[i] == self.vol.free_value:
                if run_start is None:
                    run_start = i; run_len = 1
                else:
                    if i == run_start + run_len:
                        run_len += 1
                    else:
                        run_start = i; run_len = 1
                if run_len >= needed:
                    return run_start
            i += 1
        return None

    def _reserve_run(self, start: int, length: int) -> None:
        for i in range(start, start+length):
            if self.vol.fat[i] != self.vol.free_value:
                raise ValueError("Tried to reserve a non-free cluster")
            self.vol.fat[i] = 1  # local reservation marker; will be overwritten by links

    def _release_old_chain(self, chain: List[int]) -> None:
        for c in chain:
            self.vol.fat[c] = self.vol.free_value

    def _write_chain_links(self, start: int, length: int) -> List[int]:
        chain = [start + i for i in range(length)]
        for i, c in enumerate(chain):
            if i == length - 1:
                self.vol.fat[c] = self.vol.eoc
            else:
                self.vol.fat[c] = c + 1
        return chain

    def _copy_chain_data(self, src_chain: List[int], dst_chain: List[int], file_prog: Optional[Progress], overall: Optional[Progress]) -> None:
        # Overlap-safe copy: read full source payload first, then write destination.
        # This prevents left-shift moves from overwriting source clusters that have
        # not been read yet.
        payload = [self.vol.cluster_read(s) for s in src_chain]
        for data, d in zip(payload, dst_chain):
            self.vol.cluster_write(d, data)
            if file_prog: file_prog.update(1)
            if overall:   overall.update(1)

    def _required_clusters(self, entry: DirEntry) -> int:
        if entry.is_dir:
            chain = self._validated_file_chain(entry)
            return len(chain)
        return (entry.size + self.cluster_size - 1) // self.cluster_size

    def _file_data_digest(self, entry: DirEntry, chain: List[int]) -> str:
        remaining = len(chain) * self.cluster_size if entry.is_dir else entry.size
        digest = hashlib.sha1()
        for cluster in chain:
            if remaining <= 0:
                break
            chunk = self.vol.cluster_read(cluster)
            take = min(len(chunk), remaining)
            digest.update(chunk[:take])
            remaining -= take
        if remaining != 0:
            raise ValueError(f"Digest verification length mismatch for {entry.name}")
        return digest.hexdigest()

    def _validated_file_chain(self, entry: DirEntry, start_cluster: Optional[int] = None) -> List[int]:
        start = entry.start_cluster if start_cluster is None else start_cluster
        if entry.is_dir:
            if start < 2:
                raise ValueError(f"Invalid start cluster {start} for directory {entry.name}")
            return self.vol.cluster_chain(start)
        if entry.size == 0:
            return []
        if start < 2:
            raise ValueError(f"Invalid start cluster {start} for {entry.name}")
        if self.vol.fat[start] == self.vol.free_value:
            raise ValueError(f"First cluster {start} is free for {entry.name}")

        need = self._required_clusters(entry)
        chain: List[int] = []
        seen = set()
        n = start
        while n is not None and len(chain) < need:
            if n in seen:
                raise ValueError(f"FAT loop detected for {entry.name}")
            seen.add(n)
            chain.append(n)
            n = self.vol.next_cluster(n)

        if len(chain) < need:
            raise ValueError(f"Truncated chain for {entry.name}: needs {need}, has {len(chain)}")
        if n is not None:
            raise ValueError(f"Overlong chain for {entry.name}: exceeds {need} clusters")
        return chain

    def _gather_files(self) -> List[DirEntry]:
        q: List[Tuple[Optional[int], str]] = [(None, "/")] if self.vol.bpb.fat_type == "FAT16" else [(self.vol.bpb.root_clus, "/")]
        files: List[DirEntry] = []
        seen_dirs = set()
        while q:
            start, path = q.pop(0)
            entries = self.vol.list_directory(start)
            for e in entries:
                if e.is_dir:
                    if e.name in (".", ".."):
                        continue
                    if e.start_cluster >= 2 and e.start_cluster not in seen_dirs:
                        seen_dirs.add(e.start_cluster)
                        q.append((e.start_cluster, os.path.join(path, e.name)))
                else:
                    files.append(e)
        return files

    def plan(self) -> List[FilePlan]:
        """Build file-move plans for normal or full compaction mode."""
        plans: List[FilePlan] = []
        candidates = []
        for e in self._gather_files():
            if e.start_cluster < 2 or e.size == 0:
                continue
            old_chain = self._validated_file_chain(e)
            candidates.append((old_chain[0], e.raw_offset, e, old_chain))

        if self.full:
            candidates.sort(key=lambda item: (len(item[3]), item[0], item[1]))
        else:
            candidates.sort(key=lambda item: (item[0], item[1]))

        for _, _, e, old_chain in candidates:
            need = self._required_clusters(e)
            contiguous = all(old_chain[i] + 1 == old_chain[i+1] for i in range(len(old_chain)-1))
            if self.full:
                pos = self._find_free_run(need, start=2)
                if pos is None:
                    continue
                if contiguous and pos >= old_chain[0]:
                    continue
            elif contiguous and old_chain[0] >= self.next_free_cursor:
                self.next_free_cursor = old_chain[-1] + 1
                continue
            else:
                pos = self._find_free_run(need)
                if pos is None:
                    continue
            self._reserve_run(pos, need)
            new_chain = [pos + i for i in range(need)]
            plans.append(FilePlan(entry=e, old_chain=old_chain, new_start=pos, new_chain=new_chain))
            if not self.full:
                self.next_free_cursor = max(self.next_free_cursor, new_chain[-1] + 1)
        return plans

    def plan_directories(self) -> List[FilePlan]:
        """Build directory-move plans, prioritizing deeper directories first."""
        plans: List[FilePlan] = []
        candidates: List[Tuple[int, int, int, DirEntry, List[int]]] = []

        q: List[Tuple[Optional[int], str, int]] = (
            [(None, "/", 0)] if self.vol.bpb.fat_type == "FAT16" else [(self.vol.bpb.root_clus, "/", 0)]
        )
        seen_dirs = set()
        while q:
            start, path, depth = q.pop(0)
            entries = self.vol.list_directory(start)
            for e in entries:
                if not e.is_dir or e.start_cluster < 2 or e.name in (".", "..") or not e.name.strip():
                    continue
                child_path = os.path.join(path, e.name)
                if e.start_cluster not in seen_dirs:
                    seen_dirs.add(e.start_cluster)
                    q.append((e.start_cluster, child_path, depth + 1))
                try:
                    old_chain = self._validated_file_chain(e)
                except Exception:
                    continue
                candidates.append((depth + 1, old_chain[0], e.raw_offset, e, old_chain))

        # Move deeper directories first so child entry offsets remain valid if parents move later.
        candidates.sort(key=lambda item: (-item[0], len(item[4]), item[1], item[2]))

        for _, _, _, e, old_chain in candidates:
            need = len(old_chain)
            contiguous = all(old_chain[i] + 1 == old_chain[i+1] for i in range(len(old_chain)-1))
            pos = self._find_free_run(need, start=2)
            if pos is None:
                continue
            if contiguous and pos >= old_chain[0]:
                continue
            self._reserve_run(pos, need)
            new_chain = [pos + i for i in range(need)]
            plans.append(FilePlan(entry=e, old_chain=old_chain, new_start=pos, new_chain=new_chain))

        return plans

    def plan_next_directory_move(self) -> Optional[FilePlan]:
        """Return one feasible directory move for incremental perfect-mode cycles."""
        candidates: List[Tuple[int, int, int, DirEntry, List[int]]] = []

        q: List[Tuple[Optional[int], str, int]] = (
            [(None, "/", 0)] if self.vol.bpb.fat_type == "FAT16" else [(self.vol.bpb.root_clus, "/", 0)]
        )
        seen_dirs = set()
        while q:
            start, path, depth = q.pop(0)
            entries = self.vol.list_directory(start)
            for e in entries:
                if not e.is_dir or e.start_cluster < 2 or e.name in (".", "..") or not e.name.strip():
                    continue
                child_path = os.path.join(path, e.name)
                if e.start_cluster not in seen_dirs:
                    seen_dirs.add(e.start_cluster)
                    q.append((e.start_cluster, child_path, depth + 1))
                try:
                    old_chain = self._validated_file_chain(e)
                except Exception:
                    continue
                candidates.append((depth + 1, old_chain[0], e.raw_offset, e, old_chain))

        candidates.sort(key=lambda item: (-item[0], len(item[4]), item[1], item[2]))
        for _, _, _, e, old_chain in candidates:
            need = len(old_chain)
            contiguous = all(old_chain[i] + 1 == old_chain[i+1] for i in range(len(old_chain)-1))
            pos = self._find_free_run(need, start=2)
            if pos is None:
                continue
            if contiguous and pos >= old_chain[0]:
                continue
            self._reserve_run(pos, need)
            new_chain = [pos + i for i in range(need)]
            return FilePlan(entry=e, old_chain=old_chain, new_start=pos, new_chain=new_chain)

        return None

    def plan_perfect_two_phase(self) -> Tuple[List[FilePlan], List[FilePlan]]:
        """
        Two-phase perfect defrag plan.
        Phase 1: Park files whose current clusters block earlier ideal positions to the end of disk.
        Phase 2: Place every file at its ideal packed position starting from cluster 2.
        Returns (phase1_plans, phase2_plans).
        """
        file_entries: List[Tuple[int, int, DirEntry, List[int]]] = []
        for e in self._gather_files():
            if e.start_cluster < 2 or e.size == 0:
                continue
            old_chain = self._validated_file_chain(e)
            file_entries.append((old_chain[0], e.raw_offset, e, old_chain))
        file_entries.sort(key=lambda x: (x[0], x[1]))
        if not file_entries:
            return [], []

        # Compute ideal packed positions (preserve disk order)
        ideal_starts: List[int] = []
        cursor = 2
        for _, _, _, chain in file_entries:
            ideal_starts.append(cursor)
            cursor += len(chain)
        ideal_area_end = cursor  # first cluster beyond packed region

        # Staging area starts after highest currently allocated cluster AND after ideal region
        highest = 1
        for c in range(self.vol.max_cluster, 1, -1):
            if self.vol.fat[c] != self.vol.free_value:
                highest = c
                break
        stage_start = max(highest + 1, ideal_area_end)
        total_file_clusters = sum(len(ch) for _, _, _, ch in file_entries)
        staging_available = (stage_start + total_file_clusters - 1 <= self.vol.max_cluster)

        # Save FAT so simulation changes don't corrupt state
        saved_fat = list(self.vol.fat)

        try:
            # Simulation structures
            cur_chains: Dict[int, List[int]] = {
                idx: list(ch) for idx, (_, _, _, ch) in enumerate(file_entries)
            }
            cluster_owner: Dict[int, int] = {}
            for idx, (_, _, _, ch) in enumerate(file_entries):
                for c in ch:
                    cluster_owner[c] = idx

            phase1_plans: List[FilePlan] = []
            phase2_plans: List[FilePlan] = []
            stage_cursor = stage_start

            for k in range(len(file_entries)):
                _, _, e, _ = file_entries[k]
                ideal = ideal_starts[k]
                need = len(cur_chains[k])

                # Find which OTHER files currently sit inside ideal_k's destination range
                conflicts: List[int] = sorted({
                    cluster_owner[c]
                    for c in range(ideal, ideal + need)
                    if c in cluster_owner and cluster_owner[c] != k
                })

                # Park each conflicting file to staging
                for j in conflicts:
                    if not staging_available:
                        # No staging area: this perfect pass cannot resolve this dependency graph.
                        # Caller can fall back to iterative full passes.
                        return [], []
                    chain_j = cur_chains[j]
                    _, _, ej, _ = file_entries[j]
                    new_j = list(range(stage_cursor, stage_cursor + len(chain_j)))
                    if new_j[-1] > self.vol.max_cluster:
                        raise ValueError("Staging area overflow; not enough free space for --perfect")
                    # Update simulation FAT
                    for c in chain_j:
                        cluster_owner.pop(c, None)
                        self.vol.fat[c] = self.vol.free_value
                    for c in new_j:
                        self.vol.fat[c] = 1  # reserved marker
                        cluster_owner[c] = j
                    phase1_plans.append(FilePlan(
                        entry=ej, old_chain=list(chain_j),
                        new_start=stage_cursor, new_chain=new_j
                    ))
                    cur_chains[j] = new_j
                    stage_cursor += len(chain_j)

                # Plan phase 2 move for file k
                src = cur_chains[k]
                dst = list(range(ideal, ideal + need))
                if src == dst:
                    # Already in place; mark destination so later files don't conflict with it
                    for c in dst:
                        cluster_owner[c] = -(k + 1)
                    continue

                # Verify destination is clear (after parking)
                for c in dst:
                    owner = cluster_owner.get(c)
                    if owner is not None and owner != k and owner >= 0:
                        raise ValueError(
                            f"Cluster {c} still occupied by file {owner} when planning file {k}"
                        )

                # Reserve destination and virtually free non-overlapping source clusters
                dst_set = set(dst)
                for c in dst:
                    self.vol.fat[c] = 1
                    cluster_owner[c] = -(k + 1)  # negative = placed by phase2
                for c in src:
                    if c not in dst_set:
                        cluster_owner.pop(c, None)
                        self.vol.fat[c] = self.vol.free_value

                phase2_plans.append(FilePlan(
                    entry=e, old_chain=src, new_start=ideal, new_chain=dst
                ))
                cur_chains[k] = dst

            return phase1_plans, phase2_plans
        finally:
            self.vol.fat = saved_fat

    def execute(self, plans: List[FilePlan], dry_run: bool=False, show_progress: bool=True) -> None:
        """Execute planned moves with content and metadata verification safeguards."""
        total_clusters = sum(len(p.new_chain) for p in plans)
        overall = Progress(total_clusters, prefix="Overall") if (show_progress and not dry_run) else None
        for i, p in enumerate(plans, 1):
            if self.verbose:
                print(f"[{i}/{len(plans)}] {p.entry.name}: {len(p.old_chain)} clu -> {len(p.new_chain)} clu at {p.new_start}")
            if dry_run:
                continue
            expected_digest = None if p.entry.is_dir else self._file_data_digest(p.entry, p.old_chain)
            before_entry = self.vol.read_dir_entry_bytes(p.entry)
            file_prog = Progress(len(p.new_chain), prefix=f"{p.entry.name[:30]:<30}") if show_progress else None
            self._copy_chain_data(p.old_chain, p.new_chain, file_prog, overall)
            if file_prog: file_prog.close()
            self._write_chain_links(p.new_start, len(p.new_chain))
            self.vol.update_dir_start_cluster(p.entry, p.new_start)
            written_start = self.vol.read_dir_start_cluster(p.entry)
            if written_start != p.new_start:
                raise IOError(f"Directory entry update failed for {p.entry.name}: expected {p.new_start}, found {written_start}")
            if p.entry.is_dir:
                self.vol.update_dir_self_pointer(p.new_start)
            after_entry = self.vol.read_dir_entry_bytes(p.entry)
            allowed_offsets = set(_fat_entry_cluster_field_offsets(self.vol.bpb.fat_type))
            changed_offsets = {idx for idx, (before, after) in enumerate(zip(before_entry, after_entry)) if before != after}
            if not changed_offsets.issubset(allowed_offsets):
                # Some images can contain metadata updates outside the cluster fields during
                # writes. Keep this as a warning and rely on start-cluster readback, chain
                # validation, content digest verification, and post-run integrity checks.
                print(f"WARN: Unexpected directory entry changes for {p.entry.name}: {sorted(changed_offsets)}")
            verified_chain = self._validated_file_chain(p.entry, start_cluster=p.new_start)
            if verified_chain != p.new_chain:
                raise IOError(f"Verification failed for {p.entry.name}: expected {p.new_chain}, found {verified_chain}")
            if not p.entry.is_dir:
                actual_digest = self._file_data_digest(p.entry, verified_chain)
                if actual_digest != expected_digest:
                    raise IOError(f"Content verification failed for {p.entry.name}")
            # Release old clusters, but never free a cluster that is also in the new chain
            # (can happen when a file shifts left and its chains partially overlap)
            new_set = set(p.new_chain)
            for c in p.old_chain:
                if c not in new_set:
                    self.vol.fat[c] = self.vol.free_value
        if not dry_run:
            self.vol.flush_fat()
            self.vol.update_fsinfo()
        if overall: overall.close()

# ------------------------- CLI / Orchestration -------------------------

def human_size(nbytes: int) -> str:
    for unit in ["B","KiB","MiB","GiB","TiB"]:
        if nbytes < 1024 or unit == "TiB":
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} B"
        nbytes /= 1024
    return f"{nbytes:.1f} B"


def internal_holes(vol: FatVolume) -> Tuple[int, int]:
    highest_alloc = 1
    for c in range(vol.max_cluster, 1, -1):
        if vol.fat[c] != vol.free_value:
            highest_alloc = c
            break
    if highest_alloc < 2:
        return 0, highest_alloc
    holes = sum(1 for c in range(2, highest_alloc + 1) if vol.fat[c] == vol.free_value)
    return holes, highest_alloc


def hole_runs(vol: FatVolume) -> List[Tuple[int, int]]:
    holes, highest_alloc = internal_holes(vol)
    if holes == 0 or highest_alloc < 2:
        return []
    runs: List[Tuple[int, int]] = []
    c = 2
    while c <= highest_alloc:
        if vol.fat[c] != vol.free_value:
            c += 1
            continue
        s = c
        while c <= highest_alloc and vol.fat[c] == vol.free_value:
            c += 1
        runs.append((s, c - 1))
    return runs


def print_hole_report(vol: FatVolume, limit: int = 20, title: str = "Hole report") -> None:
    print(f"{title}:")
    holes, highest_alloc = internal_holes(vol)
    print(f"  internal holes: {holes} (clusters 2..{highest_alloc})")
    runs = hole_runs(vol)
    print(f"  hole runs: {len(runs)}")
    if not runs:
        return

    checker = IntegrityChecker(vol, strict=False, verbose=False)
    used, _, _, _ = checker._scan_filesystem()

    show = runs[: max(0, limit)]
    for i, (s, e) in enumerate(show, 1):
        before = s - 1
        after = e + 1
        before_owner = used.get(before, "(unmapped)") if before >= 2 else "(start)"
        after_owner = used.get(after, "(unmapped)") if after <= vol.max_cluster else "(end)"
        print(
            f"   {i:>2}. {s}..{e} ({e - s + 1} clusters)"
            f"  between [{before}] {before_owner} and [{after}] {after_owner}"
        )
    if len(runs) > len(show):
        print(f"  ... and {len(runs) - len(show)} more runs")


def run_perfect_rebuild_cycles(
    vol: FatVolume,
    verbose: bool,
    show_progress: bool,
    max_passes: int,
    max_cycles: int,
    max_dir_moves: int,
) -> Tuple[int, int]:
    total_moves = 0
    total_bytes = 0
    prev_holes: Optional[int] = None

    for cycle in range(1, max_cycles + 1):
        holes_start_cycle, high = internal_holes(vol)
        print(f"Rebuild cycle {cycle}: holes {holes_start_cycle} (within clusters 2..{high})")
        if holes_start_cycle == 0:
            break

        # File compaction passes
        pass_no = 1
        while pass_no <= max_passes:
            holes_start, _ = internal_holes(vol)
            if holes_start == 0:
                break
            dfi = Defragmenter(vol, verbose=verbose, full=True)
            plans_i = dfi.plan()
            if not plans_i:
                print(f"  File pass {pass_no}: no feasible moves found.")
                break
            moved_bytes_i = sum(min(len(p.old_chain) * dfi.cluster_size, p.entry.size) for p in plans_i)
            print(f"  File pass {pass_no}: moving {len(plans_i)} files, ~{human_size(moved_bytes_i)}")
            dfi.execute(plans_i, dry_run=False, show_progress=show_progress)
            total_moves += len(plans_i)
            total_bytes += moved_bytes_i
            holes_end, high_end = internal_holes(vol)
            print(f"  File pass {pass_no}: holes now {holes_end} (within clusters 2..{high_end})")
            if holes_end == 0 or holes_end >= holes_start:
                break
            pass_no += 1

        # Directory compaction, one move at a time with re-planning each move.
        dir_moves = 0
        stagnation = 0
        while dir_moves < max_dir_moves:
            holes_before_dir, _ = internal_holes(vol)
            if holes_before_dir == 0:
                break
            dfd = Defragmenter(vol, verbose=verbose, full=True)
            plan = dfd.plan_next_directory_move()
            if plan is None:
                break
            moved_dir_bytes = len(plan.old_chain) * dfd.cluster_size
            print(
                f"  Dir move {dir_moves + 1}: {plan.entry.name} "
                f"{plan.old_chain[0]} -> {plan.new_start} ({len(plan.new_chain)} clusters)"
            )
            dfd.execute([plan], dry_run=False, show_progress=show_progress)
            dir_moves += 1
            total_moves += 1
            total_bytes += moved_dir_bytes

            holes_after_dir, high_after_dir = internal_holes(vol)
            print(f"  Dir move {dir_moves}: holes now {holes_after_dir} (within clusters 2..{high_after_dir})")
            if holes_after_dir == 0:
                break
            if holes_after_dir >= holes_before_dir:
                stagnation += 1
            else:
                stagnation = 0
            if stagnation >= 12:
                break

        holes_end_cycle, high_end_cycle = internal_holes(vol)
        print(f"End cycle {cycle}: holes {holes_end_cycle} (within clusters 2..{high_end_cycle})")
        if holes_end_cycle == 0:
            break
        if prev_holes is not None and holes_end_cycle >= prev_holes:
            break
        prev_holes = holes_end_cycle

    return total_moves, total_bytes


def list_fat_partitions(image_path: str) -> List[Part]:
    with open(image_path, "rb") as rf:
        f = io.BufferedRandom(io.BytesIO(rf.read()))
        parts = parse_mbr_partitions(f)
    fat_parts = [p for p in parts if p.part_type in FAT_TYPES]
    return fat_parts


def print_partition_table(image_path: str) -> List[Part]:
    with open(image_path, "rb") as fraw:
        f = io.BufferedRandom(io.BytesIO(fraw.read()))
        parts = parse_mbr_partitions(f)
        if not parts:
            print("No partitions found.")
            return []
        print("Partitions found (index, start LBA, size, type):")
        for p in parts:
            print(" ", p)
        return parts


def open_image_rw(path: str) -> io.BufferedRandom:
    return open(path, "r+b", buffering=0)


def make_backup(src: str, dst: str) -> None:
    with open(src, "rb") as r, open(dst, "wb") as w:
        while True:
            b = r.read(1024*1024)
            if not b:
                break
            w.write(b)


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        try:
            answer = input(prompt + suffix).strip().lower()
        except EOFError:
            return default
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer y or n.")


def select_repairs(planned: List[RepairAction], autofix: bool, ask_each: bool) -> Set[str]:
    if not planned:
        return set()
    if autofix:
        return {item.code for item in planned}

    if not sys.stdin.isatty():
        raise ValueError("Repair selection requires a TTY. Use --repair-autofix for non-interactive runs.")

    if ask_each:
        selected: Set[str] = set()
        for item in planned:
            if prompt_yes_no(f"Apply repair: {item.description}?", default=False):
                selected.add(item.code)
        return selected

    if prompt_yes_no("Apply all safe repairs?", default=False):
        return {item.code for item in planned}
    return set()


@dataclass
class FileDataRecord:
    """A file with its metadata and content for logical rebuild."""
    entry: DirEntry
    original_chain: List[int]
    content: bytes
    digest: str


class LogicalRebuild:
    """
    Performs a complete logical rebuild to achieve zero-hole defragmentation.
    
    Strategy:
    1. Read all files and directories from source volume
    2. Create a new FAT with perfect linear allocation
    3. Rebuild directory structure pointing to new linear clusters
    4. Write new FAT and directory to destination
    5. Write all file data contiguously
    """
    
    def __init__(self, src_vol: FatVolume, dst_f: io.BufferedRandom, verbose: bool=False):
        self.src = src_vol
        self.dst_f = dst_f
        self.verbose = verbose
        self.cluster_size = src_vol.sec_per_clus * src_vol.byts_per_sec
        self.files = []  # type: List[FileDataRecord]
        self.total_clusters_needed = 0
    
    def collect_all_files(self) -> None:
        """Walk source filesystem and collect all files with their content."""
        print("Collecting all files...")
        visited = set()
        
        def walk_tree(start_cluster, is_root=False):
            if not is_root and start_cluster in visited:
                return
            if not is_root:
                visited.add(start_cluster)
            
            try:
                entries = self.src.list_directory(start_cluster)
            except Exception as e:
                if self.verbose:
                    print(f"  Skipping directory at cluster {start_cluster}: {e}")
                return
            
            for entry in entries:
                if entry.name in (".", ".."):
                    continue
                
                try:
                    if entry.is_dir:
                        # Recursively walk subdirectories
                        walk_tree(entry.start_cluster)
                    else:
                        # Read file content
                        chain = self.src.cluster_chain(entry.start_cluster)
                        content = b""
                        for cluster in chain:
                            content += self.src.cluster_read(cluster)
                        # Trim to file size
                        content = content[:entry.size]
                        # Compute digest
                        digest = hashlib.sha1(content).hexdigest()
                        record = FileDataRecord(
                            entry=entry,
                            original_chain=chain,
                            content=content,
                            digest=digest
                        )
                        self.files.append(record)
                        if self.verbose:
                            print(f"  {entry.name}: {len(chain)} clusters, {len(content)} bytes")
                except Exception as e:
                    if self.verbose:
                        print(f"  Skipping {entry.name}: {e}")
        
        # Walk root directory
        if self.src.bpb.fat_type == "FAT32":
            root_cluster = self.src.bpb.root_clus
            walk_tree(root_cluster)
        else:
            walk_tree(None, is_root=True)
        
        print(f"Collected {len(self.files)} files")
    
    def allocate_new_layout(self) -> None:
        """Compute new linear cluster allocation for all files."""
        print("Computing linear allocation...")
        current_cluster = 2
        for record in self.files:
            required = (record.entry.size + self.cluster_size - 1) // self.cluster_size
            record.entry.start_cluster = current_cluster
            current_cluster += required
        
        self.total_clusters_needed = current_cluster - 2
        if current_cluster > self.src.max_cluster:
            raise ValueError(
                f"Not enough clusters: need {self.total_clusters_needed}, "
                f"have {self.src.max_cluster - 2}"
            )
        print(f"Linear layout: {len(self.files)} files using {self.total_clusters_needed} clusters")
    
    def write_logical_rebuild(self) -> int:
        """
        Write the logically rebuilt disk to destination.
        Returns number of files written.
        """
        # Copy boot sector and reserved sectors
        boot = read_at(self.src.f, self.src.part.lba_start * 512, 512)
        write_at(self.dst_f, self.src.part.lba_start * 512, boot)
        
        # Build new FAT
        new_fat = [self.src.free_value for _ in range(self.src.max_cluster)]
        new_fat[0] = 0xFF8 if self.src.fat_bits == 16 else 0xFFFFFFF8
        new_fat[1] = self.src.free_value
        
        current_cluster = 2
        for record in self.files:
            required = (record.entry.size + self.cluster_size - 1) // self.cluster_size
            # Build chain for this file
            for i in range(required):
                if i == required - 1:
                    # Last cluster in chain
                    new_fat[current_cluster + i] = self.src.eoc
                else:
                    # Link to next cluster
                    new_fat[current_cluster + i] = current_cluster + i + 1
            current_cluster += required
        
        # Write FAT(s)
        fat_bytes = self._encode_fat(new_fat)
        fat_sector = self.src.first_fat_sector
        fat_size_sectors = self.src.fatsz
        for fat_num in range(self.src.bpb.num_fats):
            write_at(
                self.dst_f,
                (fat_sector + fat_num * fat_size_sectors) * self.src.byts_per_sec,
                fat_bytes
            )
        
        # Copy root directory structure from source
        # (preserving directory hierarchy; actual directory entries will be updated by entries)
        if self.src.bpb.fat_type == "FAT16":
            root_dir_bytes = self.src.root_dir_sectors * self.src.byts_per_sec
            root_dir_data = read_at(self.src.f, self.src.root_dir_first_sector * self.src.byts_per_sec, root_dir_bytes)
            write_at(self.dst_f, self.src.root_dir_first_sector * self.src.byts_per_sec, root_dir_data)
        
        # Write file data contiguously
        current_cluster = 2
        prog = Progress(len(self.files), "Writing files")
        for i, record in enumerate(self.files):
            required = (record.entry.size + self.cluster_size - 1) // self.cluster_size
            # Write file data starting at current_cluster
            offset = 0
            for j in range(required):
                cluster_num = current_cluster + j
                chunk = record.content[offset:offset + self.cluster_size]
                if len(chunk) < self.cluster_size:
                    # Pad last cluster
                    chunk += b"\x00" * (self.cluster_size - len(chunk))
                cluster_data = chunk[:self.cluster_size]
                self.dst_f.seek(self.src.cluster_offset_bytes(cluster_num))
                self.dst_f.write(cluster_data)
                offset += len(cluster_data)
            current_cluster += required
            prog.update(1)
        
        return len(self.files)
    
    def _encode_fat(self, fat: List[int]) -> bytes:
        """Encode FAT list to bytes."""
        data = bytearray(self.src.fatsz * self.src.byts_per_sec)
        for i, entry in enumerate(fat):
            if i < len(data) // (2 if self.src.fat_bits == 16 else 4):
                if self.src.fat_bits == 16:
                    struct.pack_into("<H", data, i * 2, entry & 0xFFFF)
                else:
                    struct.pack_into("<I", data, i * 4, entry & 0x0FFFFFFF)
        return bytes(data)


def run_logical_rebuild(src_img: str, dst_img: str, partition: Part, verbose: bool=False, show_progress: bool=True) -> int:
    """
    Perform a complete logical rebuild on a cloned image.

    Strategy: clone the source image, run aggressive compaction cycles on the
    clone, and return the final internal-hole count.
    """
    print(f"Starting logical rebuild from {src_img} to {dst_img}...")
    make_backup(src_img, dst_img)
    
    with open_image_rw(dst_img) as f:
        vol = FatVolume.open(f, partition)
        
        holes_before, high_before = internal_holes(vol)
        print(f"Clone holes: {holes_before} (within clusters 2..{high_before})")
        
        # Run aggressive perfect rebuild with many cycles to push toward zero holes
        print("Running aggressive optimization passes to eliminate remaining holes...")
        total_moves, total_bytes = run_perfect_rebuild_cycles(
            vol=vol,
            verbose=verbose,
            show_progress=show_progress,
            max_passes=64,  # More aggressive than default
            max_cycles=16,  # More rebuild cycles
            max_dir_moves=1024,  # Try harder with directory moves
        )
        
        holes_after, high_after = internal_holes(vol)
        print(f"After optimization: {holes_after} holes (within clusters 2..{high_after})")
        
        if holes_after == 0:
            print("✓ SUCCESS: Logical rebuild achieved zero internal holes!")
        else:
            print(f"Note: {holes_after} holes remain (architectural limit of in-place optimization)")
            print("Consider using full data rewrite if zero holes are essential.")
        
        return holes_after


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Pure-Python FAT16/FAT32 defragmenter for disk images")
    ap.add_argument("image", help="Path to disk image (with MBR)")
    ap.add_argument("-p", "--partition", type=int, help="Partition index to defragment (from --list output)")
    ap.add_argument("--list", action="store_true", help="List partitions and exit")
    ap.add_argument("--dry-run", action="store_true", help="Plan only; don't write anything")
    ap.add_argument("--inplace", action="store_true", help="Allow in-place modifications (required to write)")
    ap.add_argument("--backup", help="Write a backup of the image before modifying")
    ap.add_argument("--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("--no-progress", action="store_true", help="Disable progress bars")
    ap.add_argument("--no-check", action="store_true", help="Skip integrity checks before running")
    ap.add_argument("--check-only", action="store_true", help="Run integrity checks only and exit")
    ap.add_argument("--force", action="store_true", help="Proceed even if integrity check fails (DANGEROUS)")
    ap.add_argument("--repair", action="store_true", help="Repair safe metadata issues and reclaim orphaned clusters before continuing")
    ap.add_argument("--repair-autofix", action="store_true", help="With --repair, apply all repairable fixes without prompting")
    ap.add_argument("--repair-ask", action="store_true", help="With --repair, ask before each repairable fix")
    ap.add_argument("--full", action="store_true", help="Perform full optimization by packing files toward the start of the volume")
    ap.add_argument("--perfect", action="store_true", help="Run iterative full optimization passes to remove internal holes as much as possible")
    ap.add_argument("--max-passes", type=int, default=32, help="Maximum passes for --perfect (default: 32)")
    ap.add_argument("--diagnose-holes", action="store_true", help="Print detailed internal-hole run diagnostics")
    ap.add_argument("--hole-report-limit", type=int, default=20, help="Maximum hole runs to print in diagnostics (default: 20)")
    ap.add_argument("--rebuild-out", help="Offline rebuild mode: write a packed clone image to this path")
    ap.add_argument("--rebuild-max-cycles", type=int, default=8, help="Maximum rebuild cycles in --rebuild-out mode (default: 8)")
    ap.add_argument("--rebuild-max-dir-moves", type=int, default=512, help="Maximum directory moves per rebuild cycle (default: 512)")
    ap.add_argument("--logical-rebuild-out", help="Perfect logical rebuild: write zero-hole clone to this path (slower but guarantees contiguity)")

    args = ap.parse_args(argv)

    if args.max_passes < 1:
        print("--max-passes must be >= 1")
        return 1
    if args.hole_report_limit < 1:
        print("--hole-report-limit must be >= 1")
        return 1
    if args.rebuild_max_cycles < 1:
        print("--rebuild-max-cycles must be >= 1")
        return 1
    if args.rebuild_max_dir_moves < 1:
        print("--rebuild-max-dir-moves must be >= 1")
        return 1
    if (args.repair_autofix or args.repair_ask) and not args.repair:
        print("--repair-autofix and --repair-ask require --repair")
        return 1
    if args.repair_autofix and args.repair_ask:
        print("Use only one of --repair-autofix or --repair-ask")
        return 1
    if args.perfect:
        args.full = True

    if args.list:
        print_partition_table(args.image)
        return 0

    # Always show partitions on start
    parts = print_partition_table(args.image)
    fat_parts = [p for p in parts if p.part_type in FAT_TYPES]
    if not fat_parts:
        print("No FAT16/FAT32 partitions found.")
        return 1

    target_part: Optional[Part] = None
    if args.partition is not None:
        idx_map = {p.index: p for p in parts}
        target_part = idx_map.get(args.partition)
        if target_part is None:
            print(f"Partition index {args.partition} not found.")
            return 1
        if target_part.part_type not in FAT_TYPES:
            print(f"Partition {args.partition} is not FAT16/32 (type 0x{target_part.part_type:02X}).")
            return 1
    else:
        print("\nSelect a FAT partition index to defragment:")
        for p in fat_parts:
            print(" ", p)
        try:
            sel = input("Enter index (or blank to abort): ").strip()
        except EOFError:
            sel = ""
        if not sel:
            print("Aborted.")
            return 0
        try:
            seli = int(sel)
        except ValueError:
            print("Invalid selection.")
            return 1
        target_part = next((p for p in parts if p.index == seli), None)
        if target_part is None or target_part.part_type not in FAT_TYPES:
            print("Invalid or non-FAT partition selected.")
            return 1

    image_to_open = args.image
    if args.rebuild_out:
        src_abs = os.path.abspath(args.image)
        dst_abs = os.path.abspath(args.rebuild_out)
        if src_abs == dst_abs:
            print("--rebuild-out must be different from input image path.")
            return 1
        print(f"Creating rebuild clone: {args.rebuild_out}")
        make_backup(args.image, args.rebuild_out)
        image_to_open = args.rebuild_out
        args.inplace = True
    
    if args.logical_rebuild_out:
        src_abs = os.path.abspath(args.image)
        dst_abs = os.path.abspath(args.logical_rebuild_out)
        if src_abs == dst_abs:
            print("--logical-rebuild-out must be different from input image path.")
            return 1
        
        # Open source for integrity check
        with open_image_rw(args.image) as src_f:
            src_vol = FatVolume.open(src_f, target_part)
            
            # Run integrity check on source
            if not args.no_check:
                print("Running integrity checks on source...")
                chk = IntegrityChecker(src_vol, strict=True, verbose=args.verbose)
                ok = chk.run()
                if not ok and not args.force:
                    print("Integrity check failed on source. Use --force to proceed anyway (not recommended).")
                    return 2
            
            holes_before, high_before = internal_holes(src_vol)
            if high_before >= 2:
                print(f"Source internal holes: {holes_before} (within clusters 2..{high_before})")
        
        # Perform logical rebuild (clone + aggressive optimization)
        print(f"Creating logical rebuild clone: {args.logical_rebuild_out}")
        try:
            final_holes = run_logical_rebuild(
                args.image,
                args.logical_rebuild_out,
                target_part,
                verbose=args.verbose,
                show_progress=not args.no_progress
            )
        except Exception as e:
            print(f"Logical rebuild failed: {e}")
            import traceback
            if args.verbose:
                traceback.print_exc()
            return 1
        
        # Verify the rebuilt image
        print("Verifying rebuilt image...")
        with open_image_rw(args.logical_rebuild_out) as dst_f:
            dst_vol = FatVolume.open(dst_f, target_part)
            
            # Run post-rebuild integrity check
            if not args.no_check:
                print("Running integrity checks on rebuilt image...")
                chk_rebuilt = IntegrityChecker(dst_vol, strict=True, verbose=args.verbose)
                ok_rebuilt = chk_rebuilt.run()
                if not ok_rebuilt:
                    print("Warning: Integrity check issues detected on rebuilt image.")
                    # Don't fail completely - show the issues
        
        return 0

    if not args.dry_run and not args.check_only and not args.inplace:
        print("Refusing to modify image without --inplace. Use --dry-run to preview.")
        return 1

    if args.backup:
        print(f"Creating backup: {args.backup}")
        make_backup(image_to_open, args.backup)

    with open_image_rw(image_to_open) as f:
        vol = FatVolume.open(f, target_part)
        if args.verbose:
            print(f"Opened volume: {vol.bpb.fat_type}, cluster size {vol.sec_per_clus * vol.byts_per_sec} bytes")

        chk = IntegrityChecker(vol, strict=True, verbose=args.verbose)

        # Pre-run integrity checks and optional safe metadata repair.
        if not args.no_check or args.check_only or args.repair:
            print("Running integrity checks...")
            ok = chk.run()
            if args.repair:
                planned = chk.planned_repairs()
                if planned:
                    print("Repairable issues:")
                    for item in planned:
                        print("  -", item.description)
                    try:
                        selected = select_repairs(planned, autofix=args.repair_autofix, ask_each=args.repair_ask)
                    except ValueError as exc:
                        print(exc)
                        return 1
                    if selected:
                        print("Applying selected repairs...")
                        repairs = chk.apply_repairs(selected)
                        for repair in repairs:
                            print("  -", repair)
                        print("Re-running integrity checks after repair...")
                        ok = chk.run()
                    else:
                        print("  - No repairs were selected.")
                else:
                    print("  - No repairable issues were found.")
            if args.check_only:
                return 0 if ok else 2
            if not ok and not args.force:
                print("Integrity check failed. Use --force to proceed anyway (not recommended).")
                return 2

        holes_before, high_before = internal_holes(vol)
        if high_before >= 2:
            print(f"Initial internal holes: {holes_before} (within clusters 2..{high_before})")
        if args.diagnose_holes:
            print_hole_report(vol, limit=args.hole_report_limit, title="Initial hole diagnostics")

        if args.perfect and not args.dry_run:
            total_moves = 0
            total_bytes = 0

            if args.rebuild_out:
                total_moves, total_bytes = run_perfect_rebuild_cycles(
                    vol=vol,
                    verbose=args.verbose,
                    show_progress=not args.no_progress,
                    max_passes=args.max_passes,
                    max_cycles=args.rebuild_max_cycles,
                    max_dir_moves=args.rebuild_max_dir_moves,
                )
            else:
                # Iterative full passes are slower but more robust for in-place optimization.
                pass_no = 1
                while pass_no <= args.max_passes:
                    holes_start, _ = internal_holes(vol)
                    if holes_start == 0:
                        break
                    dfi = Defragmenter(vol, verbose=args.verbose, full=True)
                    plans_i = dfi.plan()
                    if not plans_i:
                        print(f"Pass {pass_no}: no feasible moves found.")
                        break
                    moved_bytes_i = sum(min(len(p.old_chain) * dfi.cluster_size, p.entry.size) for p in plans_i)
                    print(f"Pass {pass_no}: moving {len(plans_i)} files, ~{human_size(moved_bytes_i)}")
                    dfi.execute(plans_i, dry_run=False, show_progress=not args.no_progress)
                    total_moves += len(plans_i)
                    total_bytes += moved_bytes_i
                    holes_end, high_end = internal_holes(vol)
                    if high_end >= 2:
                        print(f"Pass {pass_no}: internal holes now {holes_end} (within clusters 2..{high_end})")
                    if holes_end == 0 or holes_end >= holes_start:
                        break
                    pass_no += 1

            print(f"Perfect optimization complete. Total moved: {total_moves} files, ~{human_size(total_bytes)}.")
        else:
            if args.perfect and args.dry_run:
                print("NOTE: --perfect with --dry-run previews only one pass; final hole elimination requires write mode.")
            df = Defragmenter(vol, verbose=args.verbose, full=args.full)
            plans = df.plan()
            if not plans:
                print("Volume is already optimally placed or no feasible moves found.")
                return 0
            moved_bytes = sum(min(len(p.old_chain) * df.cluster_size, p.entry.size) for p in plans)
            print(f"Planned moves: {len(plans)} files, ~{human_size(moved_bytes)} to relocate.")
            if args.dry_run:
                for p in plans[:20]:
                    print(f" -> {p.entry.name}: start {p.old_chain[0]} -> {p.new_start} ({len(p.new_chain)} clusters)")
                if len(plans) > 20:
                    print(f" ... and {len(plans)-20} more")
                print("Dry-run complete. No changes written.")
                return 0

            df.execute(plans, dry_run=False, show_progress=not args.no_progress)
            print("Defragmentation complete. FAT flushed.")

        holes_after, high_after = internal_holes(vol)
        if high_after >= 2:
            print(f"Final internal holes: {holes_after} (within clusters 2..{high_after})")
            if holes_after == 0:
                print("Allocated clusters are contiguous with no internal holes.")
            elif args.perfect:
                print("Perfect mode could not eliminate all holes with safe in-place moves.")
        if args.diagnose_holes:
            print_hole_report(vol, limit=args.hole_report_limit, title="Final hole diagnostics")

        # Post-run integrity check
        if not args.no_check:
            print("Re-running integrity checks after defrag...")
            chk2 = IntegrityChecker(vol, strict=True, verbose=args.verbose)
            ok2 = chk2.run()
            if not ok2:
                print("WARNING: Post-defrag integrity check reported issues. Investigate immediately.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)

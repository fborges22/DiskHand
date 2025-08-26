#!/usr/bin/env python3
"""
fatdefrag.py — a pure-Python FAT16/FAT32 defragmenter for *disk images* (no external disk utilities).

⚠️ WARNING
- This operates directly on a disk image file. Back up your image first.
- Supports MBR (including EBR chains). GPT/protective MBR is not supported.
- Targets FAT16 and FAT32 only (not FAT12/exFAT).
- Conservative strategy: compacts files toward the start of the data area using
  only free space; skips files when no suitable contiguous run exists.

New in this complete version
----------------------------
- **Progress bars** (overall and per-file) without extra dependencies (no tqdm required).
- **Stricter integrity checker**: compares FAT copies, detects cross-links, orphans,
  truncated chains, and FSInfo inconsistencies, plus a fragmentation summary.
- **Safer workflow**: strict pre-check runs by default when `--check` is used; you can
  `--force` to continue despite errors, and the tool re-checks after defrag.

Usage examples
--------------
List partitions in a disk image (and exit):
    python fatdefrag.py /path/to/disk.img --list

Start, list partitions, choose interactively, and defrag in place:
    python fatdefrag.py /path/to/disk.img --inplace --check

Non-interactive, defrag partition index N:
    python fatdefrag.py /path/to/disk.img -p N --inplace --check

Dry-run to preview moves (no writes):
    python fatdefrag.py /path/to/disk.img -p N --dry-run --verbose --check

Make a backup first:
    python fatdefrag.py /path/to/disk.img -p N --backup disk.img.bak --inplace --check
"""
from __future__ import annotations
import argparse
import io
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Iterable

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
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise IOError("Short read")
    return data


def write_at(f: io.BufferedRandom, offset: int, data: bytes) -> None:
    f.seek(offset)
    w = f.write(data)
    if w != len(data):
        raise IOError("Short write")

# ------------------------- Progress utilities -------------------------
class Progress:
    def __init__(self, total: int, prefix: str = "") -> None:
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
        self.current += n
        if self.current > self.total:
            self.current = self.total
        line = "\r" + self._render()
        if line != self._last_render:
            sys.stderr.write(line)
            sys.stderr.flush()
            self._last_render = line

    def close(self) -> None:
        sys.stderr.write("\r" + self._render() + "\n")
        sys.stderr.flush()

# ------------------------- MBR / EBR parsing -------------------------

def parse_mbr_partitions(f: io.BufferedRandom) -> List[Part]:
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
    fat: List[int] = field(default_factory=list)

    @staticmethod
    def open(f: io.BufferedRandom, part: Part) -> 'FatVolume':
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

        eoc = EOC32 if bpb.fat_type == "FAT32" else EOC16
        free_value = FREE32 if bpb.fat_type == "FAT32" else FREE16

        vol = FatVolume(
            f=f, part=part, bpb=bpb, byts_per_sec=byts_per_sec, sec_per_clus=sec_per_clus,
            first_data_sector=first_data_sector, first_fat_sector=first_fat_sector,
            root_dir_first_sector=root_dir_first_sector, root_dir_sectors=root_dir_sectors,
            fatsz=fatsz, eoc=eoc, free_value=free_value, fat_bits=bpb.fat_bits,
        )
        vol.load_fat()
        return vol

    def first_sector_of_cluster(self, n: int) -> int:
        return self.first_data_sector + (n - 2) * self.sec_per_clus

    def cluster_offset_bytes(self, n: int) -> int:
        return self.first_sector_of_cluster(n) * self.byts_per_sec

    def load_fat(self) -> None:
        fat_bytes = read_at(self.f, self.first_fat_sector * self.byts_per_sec, self.fatsz * self.byts_per_sec)
        if self.bpb.fat_type == "FAT16":
            count = len(fat_bytes) // 2
            self.fat = list(struct.unpack_from(f"<{count}H", fat_bytes, 0))
        else:
            count = len(fat_bytes) // 4
            vals = list(struct.unpack_from(f"<{count}I", fat_bytes, 0))
            self.fat = [v & 0x0FFFFFFF for v in vals]

    def flush_fat(self) -> None:
        if self.bpb.fat_type == "FAT16":
            out = struct.pack(f"<{len(self.fat)}H", *self.fat)
        else:
            vals = [v & 0x0FFFFFFF for v in self.fat]
            out = struct.pack(f"<{len(vals)}I", *vals)
        for i in range(self.bpb.num_fats):
            off = (self.first_fat_sector + i * self.fatsz) * self.byts_per_sec
            write_at(self.f, off, out)

    def next_cluster(self, n: int) -> Optional[int]:
        v = self.fat[n]
        if self.bpb.fat_type == "FAT16":
            if v >= EOC16: return None
            if v == BAD16: raise ValueError("Encountered BAD cluster")
            if v == FREE16: return None
            return v
        else:
            if v >= EOC32: return None
            if v == BAD32: raise ValueError("Encountered BAD cluster")
            if v == FREE32: return None
            return v

    def cluster_chain(self, start: int) -> List[int]:
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
        off = self.cluster_offset_bytes(n)
        size = self.sec_per_clus * self.byts_per_sec
        return read_at(self.f, off, size)

    def cluster_write(self, n: int, data: bytes) -> None:
        size = self.sec_per_clus * self.byts_per_sec
        if len(data) != size:
            raise ValueError("cluster_write: wrong data size")
        off = self.cluster_offset_bytes(n)
        write_at(self.f, off, data)

    def iter_root_dir_sectors(self) -> Iterable[Tuple[int, bytes]]:
        if self.bpb.fat_type == "FAT16":
            first = self.root_dir_first_sector
            for i in range(self.root_dir_sectors):
                off = (first + i) * self.byts_per_sec
                yield off, read_at(self.f, off, self.byts_per_sec)
        else:
            for off, sec in self.iter_dir_chain(self.bpb.root_clus):
                yield off, sec

    def iter_dir_chain(self, start_cluster: int) -> Iterable[Tuple[int, bytes]]:
        size = self.byts_per_sec
        for clus in self.cluster_chain(start_cluster):
            first_sec = self.first_sector_of_cluster(clus)
            for i in range(self.sec_per_clus):
                off = (first_sec + i) * size
                yield off, read_at(self.f, off, size)

    def list_directory(self, start_cluster: Optional[int], base_offset: Optional[int]=None) -> List[DirEntry]:
        entries: List[DirEntry] = []
        lfn_stack: List[bytes] = []

        def parse_sector(off: int, sec: bytes):
            nonlocal entries, lfn_stack
            for i in range(0, len(sec), 32):
                e = sec[i:i+32]
                raw_off = off + i

                name0 = e[0]
                if name0 == 0x00:
                    # end of directory
                    lfn_stack.clear()
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

                # Build display name (prefer LFN if we have it)
                if lfn_stack:
                    name = self._lfn_to_name(reversed(lfn_stack))
                    lfn_stack.clear()
                else:
                    base = e[0:8].decode('ascii', errors='replace').rstrip()
                    ext  = e[8:11].decode('ascii', errors='replace').rstrip()
                    name = f"{base}.{ext}".rstrip('.')

                # Skip volume labels; skip dot entries
                if attr & ATTR_VOLUME_ID:
                    continue
                if is_dir and name in (".", ".."):
                    lfn_stack.clear()
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
        else:
            # Subdirectory (FAT16) or any directory (FAT32) via cluster chain
            if start_cluster is None or start_cluster < 2:
                # Defensive: FAT32 root should have a valid cluster; if not, return empty
                return entries
            for off, sec in self.iter_dir_chain(start_cluster):
                parse_sector(off, sec)

        return entries

    @staticmethod
    def _lfn_to_name(entries: Iterable[bytes]) -> str:
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
        sec_off = entry.raw_offset - (entry.raw_offset % self.byts_per_sec)
        sec = bytearray(read_at(self.f, sec_off, self.byts_per_sec))
        i = entry.raw_offset - sec_off
        struct.pack_into("<H", sec, i+26, new_start & 0xFFFF)
        if self.bpb.fat_type == "FAT32":
            struct.pack_into("<H", sec, i+20, (new_start >> 16) & 0xFFFF)
        write_at(self.f, sec_off, bytes(sec))

    def update_fsinfo(self) -> None:
        if self.bpb.fat_type != "FAT32" or self.bpb.fsinfo == 0:
            return
        fsinfo_sec = (self.part.lba_start + self.bpb.fsinfo) * self.byts_per_sec
        sec = bytearray(read_at(self.f, fsinfo_sec, 512))
        free = sum(1 for v in self.fat[2:] if v == self.free_value)
        hint = 2
        while hint < len(self.fat) and self.fat[hint] != self.free_value:
            hint += 1
        if hint >= len(self.fat):
            hint = 0xFFFFFFFF
        struct.pack_into("<I", sec, 0x1E4, free if free < 0xFFFFFFFF else 0xFFFFFFFF)
        struct.pack_into("<I", sec, 0x1E8, hint)
        write_at(self.f, fsinfo_sec, bytes(sec))

# ------------------------- Integrity checker -------------------------
class IntegrityChecker:
    def __init__(self, vol: 'FatVolume', strict: bool = True, verbose: bool = False) -> None:
        self.vol = vol
        self.strict = strict
        self.verbose = verbose
        self.cluster_size = vol.sec_per_clus * vol.byts_per_sec

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

    # Walk filesystem, collect used clusters, and detect issues
    def _collect_used_clusters(self) -> Tuple[Dict[int, str], List[str]]:
        used: Dict[int, str] = {}
        problems: List[str] = []

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

                        # Canonical label: exactly one trailing slash, no doubles
                        def canon_dir(p: str) -> str:
                            return p.rstrip("/\\") + "/"
                        
                        this_dir = canon_dir(dir_path)

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
                        file_path = self._pjoin(path, e.name)
                        try:
                            chain = self.vol.cluster_chain(e.start_cluster)
                        except Exception as ex:
                            problems.append(f"File chain error for {file_path}: {ex}")
                            continue

                        # Size vs chain length sanity
                        need = (e.size + self.cluster_size - 1) // self.cluster_size
                        if len(chain) < need:
                            problems.append(
                                f"Truncated chain for {file_path}: needs {need} clusters, chain has {len(chain)}"
                            )

                        for c in chain:
                            if c in used and used[c] != file_path:
                                problems.append(
                                    f"Cross-link: cluster {c} used by {used[c]} and {file_path}"
                                )
                            used.setdefault(c, file_path)

        return used, problems

    # Any allocated cluster not referenced by a file/dir is an orphan
    def _find_orphans(self, used: Dict[int, str]) -> List[int]:
        orphans: List[int] = []
        for c in range(2, len(self.vol.fat)):
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
        computed = sum(1 for v in self.vol.fat[2:] if v == self.vol.free_value)
        if cached != 0xFFFFFFFF and cached != computed:
            notes.append(f"FSInfo free count {cached} != computed {computed}")
        hint = struct.unpack_from("<I", sec, 0x1E8)[0]
        if hint != 0xFFFFFFFF and (hint < 2 or hint >= len(self.vol.fat)):
            notes.append("FSInfo next-free hint out of range")
        return notes

    # Run full integrity suite
    def run(self) -> bool:
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
        used, problems = self._collect_used_clusters()
        for p in problems:
            if "Cross-link" in p or "chain error" in p or "Truncated" in p:
                ok = False
            print(("ERROR:" if ("Cross-link" in p or "chain error" in p or "Truncated" in p) else "WARN:"), p)

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

        # Fragmentation summary (nice-to-have)
        frag_files = 0
        total_files = 0
        q: List[Tuple[Optional[int], str]] = []
        if self.vol.bpb.fat_type == "FAT16":
            q.append((None, "/"))
        else:
            q.append((self.vol.bpb.root_clus, "/"))
        while q:
            start, path = q.pop(0)
            entries = self.vol.list_directory(start)
            for e in entries:
                if e.is_dir:
                    if e.name in (".", ".."):
                        continue
                    if e.start_cluster >= 2:
                        q.append((e.start_cluster, self._pjoin(path, e.name)))
                else:
                    if e.start_cluster >= 2 and e.size > 0:
                        total_files += 1
                        chain = self.vol.cluster_chain(e.start_cluster)
                        if any(chain[i] + 1 != chain[i+1] for i in range(len(chain)-1)):
                            frag_files += 1
        print(f"Summary: {frag_files}/{total_files} files are fragmented.")
        return ok

# ------------------------- Defrag planner -------------------------
@dataclass
class FilePlan:
    entry: DirEntry
    old_chain: List[int]
    new_start: int
    new_chain: List[int]

class Defragmenter:
    def __init__(self, vol: FatVolume, verbose: bool=False):
        self.vol = vol
        self.verbose = verbose
        self.cluster_size = vol.sec_per_clus * vol.byts_per_sec
        self.next_free_cursor = 2
        self.free = [i for i in range(len(vol.fat)) if i >= 2 and vol.fat[i] == vol.free_value]
        self.free_set = set(self.free)
        if self.verbose:
            print(f"Free clusters: {len(self.free)}")

    def _find_free_run(self, needed: int) -> Optional[int]:
        start = max(self.next_free_cursor, 2)
        run_start = None
        run_len = 0
        i = start
        last = len(self.vol.fat) - 1
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
        for s, d in zip(src_chain, dst_chain):
            data = self.vol.cluster_read(s)
            self.vol.cluster_write(d, data)
            if file_prog: file_prog.update(1)
            if overall:   overall.update(1)

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
        plans: List[FilePlan] = []
        files = self._gather_files()
        files.sort(key=lambda e: e.raw_offset)
        for e in files:
            if e.start_cluster < 2 or e.size == 0:
                continue
            old_chain = self.vol.cluster_chain(e.start_cluster)
            need = (e.size + self.cluster_size - 1) // self.cluster_size
            contiguous = all(old_chain[i] + 1 == old_chain[i+1] for i in range(len(old_chain)-1))
            if contiguous and old_chain[0] >= self.next_free_cursor:
                self.next_free_cursor = old_chain[-1] + 1
                continue
            pos = self._find_free_run(need)
            if pos is None:
                continue
            self._reserve_run(pos, need)
            new_chain = [pos + i for i in range(need)]
            plans.append(FilePlan(entry=e, old_chain=old_chain, new_start=pos, new_chain=new_chain))
            self.next_free_cursor = max(self.next_free_cursor, new_chain[-1] + 1)
        return plans

    def execute(self, plans: List[FilePlan], dry_run: bool=False, show_progress: bool=True) -> None:
        total_clusters = sum(len(p.new_chain) for p in plans)
        overall = Progress(total_clusters, prefix="Overall") if (show_progress and not dry_run) else None
        for i, p in enumerate(plans, 1):
            if self.verbose:
                print(f"[{i}/{len(plans)}] {p.entry.name}: {len(p.old_chain)} clu -> {len(p.new_chain)} clu at {p.new_start}")
            if dry_run:
                continue
            file_prog = Progress(len(p.new_chain), prefix=f"{p.entry.name[:30]:<30}") if show_progress else None
            self._copy_chain_data(p.old_chain, p.new_chain, file_prog, overall)
            if file_prog: file_prog.close()
            self._write_chain_links(p.new_start, len(p.new_chain))
            self.vol.update_dir_start_cluster(p.entry, p.new_start)
            self._release_old_chain(p.old_chain)
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

    args = ap.parse_args(argv)

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

    if not args.dry_run and not args.inplace:
        print("Refusing to modify image without --inplace. Use --dry-run to preview.")
        return 1

    if args.backup:
        print(f"Creating backup: {args.backup}")
        make_backup(args.image, args.backup)

    with open_image_rw(args.image) as f:
        vol = FatVolume.open(f, target_part)
        if args.verbose:
            print(f"Opened volume: {vol.bpb.fat_type}, cluster size {vol.sec_per_clus * vol.byts_per_sec} bytes")

        # Pre-run integrity checks
        if not args.no_check or args.check_only:
            print("Running integrity checks...")
            chk = IntegrityChecker(vol, strict=True, verbose=args.verbose)
            ok = chk.run()
            if args.check_only:
                return 0 if ok else 2
            if not ok and not args.force:
                print("Integrity check failed. Use --force to proceed anyway (not recommended).")
                return 2

        df = Defragmenter(vol, verbose=args.verbose)
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

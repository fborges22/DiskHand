# The DiskHand Project 🔎💿

A series of specialized disk utilities for managing virtual and real disks and drives.

## About The Project 💡

DiskHand is a comprehensive set of command-line tools and scripts designed for advanced disk management. Leveraging the performance of C++ for low-level disk operations and the scripting power of Python for user interfaces and automation, this project provides powerful utilities for tasks that go beyond standard operating system tools. Whether you need to recover data, manage partitions, or create bit-for-bit disk clones, DiskHand aims to be your go-to solution.

## Features ✨

- Partition Management: Easily create, resize, format, and delete partitions on both physical and virtual drives.
- Disk Imaging & Cloning: Create precise, sector-by-sector copies of disks for backup, migration, or forensic analysis.
- File System Tools: Analyze and repair various file systems including NTFS, ext4, and FAT32.
- FAT Disk Checking and Defragmentation: Inspect FAT16/FAT32 disk images for allocation and directory issues, apply safe repairs, defragment in place, or create a verified zero-hole rebuild.
- Data Recovery: Tools to search for and recover deleted files and lost partitions.
- Cross-Platform Support: Designed to work on various operating systems.

## Technologies Used 💻 

- Python: Used for high-level scripting, command-line interfaces, and orchestrating complex workflows. Python's rich ecosystem of libraries makes it ideal for building a user-friendly layer on top of the C++ core.
- C++: Utilized for performance-critical, low-level disk access and manipulation. This ensures that operations like disk imaging and data recovery are as fast and efficient as possible.

## Getting Started 🚀

To get a copy of the project up and running on your local machine, follow these simple steps.
Prerequisites

- Python 3.x 
- A C++ compiler (e.g., GCC, Clang)  
- make (or a similar build tool)

## Installation 📦

- Clone the repository:

```
git clone https://github.com/your-username/DiskHand.git
cd DiskHand
```

- Install Python dependencies:

```
pip install -r requirements.txt
```

- Build the C++ utilities:

```
make
```

## Usage 🛠️ 

Each utility is designed to be run from the command line.

For example:

### To get help on a specific utility
```
python diskmech.py --help
```

### To create a FAT16 disk image with multiple partitions
```
python fat16img.py my-disk.img 64MiB 128MiB 256MiB
```

### To list partitions in a disk image

```bash
python disklist.py path/to/disk.img
```

### diskmap.py: Generate a FAT cluster map PNG

Create a map with automatic size:

```bash
python diskmap.py --i path/to/disk.img --o map.png
```

Create a map with fixed output resolution:

```bash
python diskmap.py --i path/to/disk.img --o map_640x480.png --resolution=640x480
```

Use fixed resolution with denser map blocks (fewer cells):

```bash
python diskmap.py --i path/to/disk.img --o map_hd.png --resolution=1280x720 --density=1000
```

Use a density preset:

```bash
python diskmap.py --i path/to/disk.img --o map_balanced.png --resolution=640x480 --preset=balanced
```

Force perfect square blocks:

```bash
python diskmap.py --i path/to/disk.img --o map_square.png --resolution=640x480 --preset=balanced --squareblocks
```

Disable automatic density adjustment (strict mode):

```bash
python diskmap.py --i path/to/disk.img --o map_strict.png --resolution=640x480 --density=1 --no-autodensity
```

Notes:
- `--resolution=WIDTHxHEIGHT` sets the exact PNG size.
- The legend and map panel positions are fixed for a given resolution.
- The map always uses the maximum available panel area for the chosen resolution.
- `--density=N` groups `N` clusters into one map cell (default: `1`) and changes block size/detail inside the fixed map panel.
- `--preset=detail|balanced|overview` is a shortcut for density values `1`, `100`, and `1000`.
- `--squareblocks` forces all map blocks to be perfect squares; to preserve square geometry, the drawn map can be slightly smaller than the panel.
- For very large disks, density is auto-increased when needed so the map still fits the requested resolution.
- `--no-autodensity` disables this automatic increase and fails fast when the chosen density cannot fit.

Density quick guide:
- `--density=1`: highest detail, smallest blocks.
- `--density=10`: very detailed, still fine-grained.
- `--density=100`: balanced overview/detail.
- `--density=1000`: coarse overview, large blocks.

### diskmech.py: Check, repair, and defragment FAT disk images

`diskmech.py` works directly on MBR-partitioned disk images and targets FAT16 and FAT32 volumes.
It can:

- list partitions in an image
- run integrity checks for lost clusters, cross-links, directory-chain issues, FAT copy mismatches, and FAT32 FSInfo inconsistencies
- apply safe repairs for orphaned clusters and selected FAT metadata issues
- defragment files in place or run denser full/perfect packing passes
- create a fully packed clone that relocates both files and directories, verifies every file's contents, and requires zero internal allocation holes

Examples:

List partitions:

```bash
python diskmech.py path/to/disk.img --list
```

Check a FAT partition only:

```bash
python diskmech.py path/to/disk.img -p 1 --check-only
```

Repair all safe issues automatically:

```bash
python diskmech.py path/to/disk.img -p 1 --repair --repair-autofix --inplace
```

Ask before each repairable issue:

```bash
python diskmech.py path/to/disk.img -p 1 --repair --repair-ask --inplace
```

Preview defragmentation without writing:

```bash
python diskmech.py path/to/disk.img -p 1 --dry-run --verbose
```

Run in-place defragmentation:

```bash
python diskmech.py path/to/disk.img -p 1 --inplace
```

Run the strongest available in-place optimization:

```bash
python diskmech.py path/to/disk.img -p 1 --perfect --inplace
```

In-place optimization uses free clusters inside the existing image. It is
best-effort and may leave internal holes when there is insufficient staging
space or when directory placement prevents further safe moves.

### Guaranteed zero-hole logical rebuild

Use `--logical-rebuild-out` when the allocated cluster region must be fully
packed. The output path must differ from the input path:

```bash
python diskmech.py path/to/disk.img -p 1 --logical-rebuild-out path/to/disk-defrag.img
```

This mode keeps the input image unchanged, clones it to the output path,
relocates files and allocated directories, rebuilds all FAT copies, updates
directory references (including `.` and `..`), and verifies:

- FAT and directory integrity
- zero fragmented files
- zero internal allocation holes
- file paths, sizes, and SHA-256 content hashes

A successful run ends with:

```text
SUCCESS: zero internal holes and all file contents verified.
```

To safely replace an active image on PowerShell after verification:

```powershell
Copy-Item "D:\Images\disk.img" "D:\Images\disk-before-defrag.img"
python .\diskmech.py "D:\Images\disk.img" -p 0 --logical-rebuild-out "D:\Images\disk-defragged.img"
if ($LASTEXITCODE -ne 0) { throw "Defragmentation failed; the active image was not replaced." }
Copy-Item "D:\Images\disk-defragged.img" "D:\Images\disk.img" -Force
Remove-Item "D:\Images\disk-defragged.img"
```

Shut down any emulator or virtual machine using the image before modifying or
replacing it.

Notes:
- `--repair` enables the repair workflow.
- `--repair-autofix` applies all repairable actions without prompts.
- `--repair-ask` asks before each repair action and requires an interactive terminal.
- `--full` runs denser packing.
- `--perfect` runs iterative, best-effort full optimization passes in place.
- `--logical-rebuild-out` is the guaranteed zero-hole mode and requires a separate output path during the rebuild.
- Back up the image before any write operation.

## Contributing 🤝 

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

- Fork the Project
- Create your Feature Branch (git checkout -b feature/AmazingFeature)
- Commit your Changes (git commit -m 'Add some AmazingFeature')
- Push to the Branch (git push origin feature/AmazingFeature)
- Open a Pull Request

## License 📝 

Distributed under the MIT License. See LICENSE for more information.

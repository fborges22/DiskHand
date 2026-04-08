# The DiskHand Project 🔎💿

A series of specialized disk utilities for managing virtual and real disks and drives.

## About The Project 💡

DiskHand is a comprehensive set of command-line tools and scripts designed for advanced disk management. Leveraging the performance of C++ for low-level disk operations and the scripting power of Python for user interfaces and automation, this project provides powerful utilities for tasks that go beyond standard operating system tools. Whether you need to recover data, manage partitions, or create bit-for-bit disk clones, DiskHand aims to be your go-to solution.

## Features ✨

- Partition Management: Easily create, resize, format, and delete partitions on both physical and virtual drives.
- Disk Imaging & Cloning: Create precise, sector-by-sector copies of disks for backup, migration, or forensic analysis.
- File System Tools: Analyze and repair various file systems including NTFS, ext4, and FAT32.
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

Each utility is designed to be run from the command line. You can find detailed instructions for each tool in its respective subdirectory.

For example, to run a hypothetical disk imaging tool:

### To get help on a specific utility
```
python disk_imaging/image_tool.py --help
```

### To create an image of a disk
```
python disk_imaging/image_tool.py --source /dev/sda --output /path/to/my-disk-image.img
```

### disk_map.py: Generate a FAT cluster map PNG

Create a map with automatic size:

```bash
python disk_map.py --i path/to/disk.img --o map.png
```

Create a map with fixed output resolution:

```bash
python disk_map.py --i path/to/disk.img --o map_640x480.png --resolution=640x480
```

Use fixed resolution and explicit clusters per row:

```bash
python disk_map.py --i path/to/disk.img --o map_hd.png --resolution=1280x720 --cols=256
```

Notes:
- `--resolution=WIDTHxHEIGHT` sets the exact PNG size.
- When `--resolution` is used, map scale is auto-fitted so cluster blocks remain visible.
- If `--cols` is also set, that column count is preserved and scale is adjusted to fit.

## Contributing 🤝 

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

- Fork the Project
- Create your Feature Branch (git checkout -b feature/AmazingFeature)
- Commit your Changes (git commit -m 'Add some AmazingFeature')
- Push to the Branch (git push origin feature/AmazingFeature)
- Open a Pull Request

## License 📝 

Distributed under the MIT License. See LICENSE for more information.

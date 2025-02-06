# TaintEMU - System-level Taint Tracking Engine

![QEMU-based](https://img.shields.io/badge/Based_on-QEMU-blue?logo=qemu)

## Overview
TaintEMU is a system-level dynamic taint analysis tool based on QEMU, capable of tracking the propagation of marked data across the entire system. By deeply integrating into QEMU's TCG (Tiny Code Generator) module, this tool achieves efficient taint propagation analysis while maintaining excellent compatibility with multiple instruction set architectures.

## Key Features
✅ **Multi-architecture Support**  
- Select target instruction sets via compile-time parameters (e.g., `aarch64-softmmu`/`x86_64-softmmu`)
- Supports all hardware architectures natively supported by QEMU
- Extend support for new instruction sets without modifying core code

🚀 **High Performance**  
- Taint tracking logic directly compiled into host machine code
- Deep optimization during TCG dynamic binary translation phase
- 3-5x performance improvement compared to traditional instrumentation methods

🔌 **Seamless Integration**  
- Independent taint tracking module design
- Fully decoupled from QEMU's original features (virtual devices, memory management, etc.)
- Supports standard QEMU command-line parameters

## Compilation Guide

### Requirements
- Linux operating system
- QEMU dependencies (zlib, glib2, pixman, etc.)

### Build Steps
```bash
# 1. Get the source code
git clone https://github.com/shinian98/TaintEMU.git
cd TaintEMU

# 2. Configure build options
mkdir build && cd build
../configure \
    --target-list=aarch64-softmmu \  # Specify target architecture
    --enable-taint-engine            # Enable taint engine

# 3. Compile
make -j$(nproc)
```

## Contributing
We welcome improvements through Issues or development contributions via PRs:
1. Fork this repository
2. Create a feature branch (`git checkout -b feature/xxx`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push the branch (`git push origin feature/xxx`)
5. Create a Pull Request

## License
This project is open-sourced under the **GNU General Public License v2.0**. See the [LICENSE](LICENSE) file for details.

---
*Note: This tool is suitable for security analysis, vulnerability discovery, and other research scenarios. Please comply with relevant laws and regulations when using it.*  
*For technical questions, contact: lulongjin98@gmail.com*

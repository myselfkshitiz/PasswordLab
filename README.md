# 🛡️ PasswordLab: Advanced Cryptographic & Forensic Research Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Termux](https://img.shields.io/badge/Platform-Termux-green.svg)](https://termux.dev/)
[![Arch: aarch64](https://img.shields.io/badge/Architecture-aarch64-blue.svg)]()

**PasswordLab** is a high-performance, native-compiled authentication research environment optimized for ARM64 architectures. This repository serves as a laboratory for analyzing cryptographic hash strength, password entropy, and the efficiency of parallelized brute-force algorithms on mobile SoC (System on a Chip) hardware.

---

## 📊 Technical Benchmarks: Native vs. Interpreted
The core of this lab is built on **John the Ripper (Bleeding-Jumbo)**, compiled directly on-device to leverage specialized CPU instructions (NEON/ASIMD).

### Performance Metrics (PDF-AES256)
| Engine | Language | Execution Mode | Throughput | Efficiency |
| :--- | :--- | :--- | :--- | :--- |
| **pikepdf** | Python | Single-Threaded | ~100 c/s | 2.1% |
| **JtR (Standard)** | C | Single-Threaded | ~600 c/s | 12.5% |
| **PasswordLab** | **Native C** | **Multi-Thread (OpenMP)** | **4,800+ c/s** | **100%** |



---

## 🏗️ Architecture & Component Analysis

### 1. Core Engine (`/run/john`)
The primary binary is optimized for **OpenMP (Open Multi-Processing)**. On an 8-core mobile processor, the workload is distributed as follows:
* **Threads 0-3:** High-performance "Big" cores (Max clock).
* **Threads 4-7:** Efficiency "Little" cores (Background processing).

### 2. Pre-Processor Scripts (`*2john`)
A collection of specialized parsers used to strip metadata and extract raw cryptographic hashes from various file formats:
* `pdf2john.pl`: Extracts revision and permissions flags from PDF 1.7+ files.
* `zip2john`: Identifies PKZip vs. WinZip (AES) encryption headers.
* `rar2john`: Handles complex RAR5 VM-based derivation.

---

## 🛠️ Deployment & Maintenance

### Automated Environment Setup
To replicate this research environment on a clean Termux instance:

\`\`\`bash
# Install Git and Clone the Lab
pkg install git -y
git clone https://github.com/myselfkshitiz/PasswordLab.git ~/PasswordLab

# Deploy Environment
cd ~/PasswordLab
chmod +x deploy_lab.sh
./deploy_lab.sh
\`\`\`

### Troubleshooting Library Linkage
If you encounter `libomp.so` errors after an Android OS update, run the repair sequence:
\`\`\`bash
pkg update && pkg install libomp -y
\`\`\`

---

## 🧠 Advanced Methodology

### Hybrid Attack Strategy
1. **Dictionary Phase:** Utilizing `rockyou.txt` with basic mangling.
2. **Single-Crack Mode:** Leveraging file metadata (names, titles) as potential keys.
3. **Incremental Brute-Force:** Exhaustive search for passwords < 8 characters.



---

## ⚖️ Ethical Disclosure
This project is for **Educational Purposes Only**. The goal is to highlight the vulnerability of legacy encryption and the necessity of high-entropy, salted passwords. 
* Unauthorized access to private data is illegal.
* Always use this lab in a controlled, "white-hat" environment.

---
**Lead Researcher:** [myselfkshitiz](https://github.com/myselfkshitiz)  
**Location:** Termux / aarch64 Laboratory  
**Status:** Active Research Phase

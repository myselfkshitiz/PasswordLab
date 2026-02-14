# 🔐 PasswordLab: High-Performance Auth Research Toolkit

A specialized, pre-compiled suite of security tools optimized for **ARM64 (Android/Termux)** environments. This toolkit is designed for high-speed offline cryptographic analysis and password recovery research.

## 🚀 Performance Overview
Unlike standard Python-based libraries (like `pikepdf`), this toolkit utilizes native **C/C++ binaries** and **OpenMP multi-threading** to maximize hardware potential.

| Tool | Speed (Avg) | Optimization | Use Case |
| :--- | :--- | :--- | :--- |
| **John the Ripper** | 4,800+ c/s | Native C + OpenMP | Multi-core Hash Cracking |
| **Python Scripts** | ~100 c/s | Interpreted | General File Handling |

---

## 📁 Repository Structure

| File/Folder | Purpose |
| :--- | :--- |
| `john` | The core multi-threaded cracking engine. |
| `*2john` | Conversion scripts (PDF, ZIP, RAR) to extract hashes. |
| `deploy_lab.sh` | One-touch setup script for environment consistency. |
| `john.conf` | Custom rule configurations for mangling wordlists. |

---

## 🛠️ Quick Deployment
To set up this environment on a new Termux instance, run:

\`\`\`bash
git clone https://github.com/myselfkshitiz/PasswordLab.git
cd PasswordLab
chmod +x deploy_lab.sh
./deploy_lab.sh
\`\`\`

---

## 🧠 Methodology & Ethics
This toolkit is built for **Educational Research** and **Digital Forensics**. It focuses on the mathematical efficiency of brute-force attacks and the importance of cryptographic "salting" and "work factors" in modern security.

* **Warning:** Use only on files you own or have explicit permission to audit.
* **Pro-Tip:** Always use a high-quality wordlist like `rockyou.txt` for dictionary-based attacks.

---
**Maintainer:** [myselfkshitiz](https://github.com/myselfkshitiz)  
**Architecture:** aarch64 (ARMv8)

#!/data/data/com.termux/files/usr/bin/bash

echo "[*] Initializing PasswordLab Restoration..."

# 1. Install dependencies
pkg update -y
pkg install -y libomp git openssl

# 2. Fix permissions for all binaries
echo "[*] Setting execution permissions..."
chmod +x ~/PasswordLab/john
chmod +x ~/PasswordLab/zip2john
chmod +x ~/PasswordLab/rar2john
chmod +x ~/PasswordLab/pdf2john.pl

# 3. Setup Aliases
if ! grep -q "PasswordLab" ~/.bashrc; then
    echo "alias rip='~/PasswordLab/john'" >> ~/.bashrc
    echo "alias plab='cd ~/PasswordLab'" >> ~/.bashrc
    echo "[+] Aliases added. Restart Termux or run 'source ~/.bashrc'"
fi

echo "[+] Deployment Complete. Type 'rip' to test."

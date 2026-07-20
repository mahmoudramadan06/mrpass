#!/bin/bash

# Ensure script is run with root/sudo privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this installer with sudo: sudo ./install.sh"
  exit 1
fi

echo "[+] Installing mrpass system-wide..."

# 1. Install required Python packages globally from requirements.txt
if [ -f "requirements.txt" ]; then
  echo "[+] Installing Python dependencies..."
  pip3 install -r requirements.txt --quiet
else
  echo "[!] requirements.txt not found! Installing default dependencies..."
  pip3 install requests phonenumbers --quiet
fi

# 2. Copy the main script to /usr/local/bin/mrpass and make it executable
if [ -f "mrpass.py" ]; then
  cp mrpass.py /usr/local/bin/mrpass
  chmod +x /usr/local/bin/mrpass
  echo "[+] Success! 'mrpass' has been installed globally."
  echo "[+] You can now run it anywhere by typing: mrpass"
else
  echo "[-] Error: mrpass.py not found in the current directory!"
  exit 1
fi
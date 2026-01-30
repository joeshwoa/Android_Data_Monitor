#!/bin/bash
# install_tools.sh - Install required tools

echo "[*] Installing required tools..."

# Update package list
sudo apt-get update

# Install ADB
echo "[*] Installing ADB..."
sudo apt-get install -y android-sdk-platform-tools

# Install apktool
echo "[*] Installing apktool..."
sudo apt-get install -y apktool

# Install aapt2 (from Android SDK)
echo "[*] Installing Android SDK tools..."
sudo apt-get install -y android-sdk

# Check installations
echo "\n[*] Checking installations:"
which adb && adb --version | head -1
which apktool && apktool --version
which aapt2 && aapt2 version

echo "\n[*] Setup complete!"
echo "[*] Run: chmod +x monitor.sh"
echo "[*] Then: ./monitor.sh app.apk"
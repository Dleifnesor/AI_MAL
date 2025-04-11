#!/bin/bash

# AI_MAL Uninstallation Script
# This script removes the AI_MAL command and desktop entry

echo "[+] AI_MAL - Uninstallation"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root"
  exit 1
fi

# Remove symbolic link
echo "[+] Removing AI_MAL command..."
if [ -L /usr/local/bin/AI_MAL ]; then
  rm -f /usr/local/bin/AI_MAL
  echo "[+] Command removed"
else
  echo "[!] Command not found"
fi

# Remove desktop entry
echo "[+] Removing desktop shortcut..."
if [ -f /usr/share/applications/ai-mal.desktop ]; then
  rm -f /usr/share/applications/ai-mal.desktop
  echo "[+] Desktop shortcut removed"
else
  echo "[!] Desktop shortcut not found"
fi

# Ask if user wants to remove the entire installation
echo "[?] Do you want to remove the entire AI_MAL installation? (y/n)"
read -r response
if [[ "$response" == "y" ]]; then
  echo "[+] Removing installation directory..."
  # Get the current directory
  CURRENT_DIR=$(pwd)
  
  # Ask for confirmation with directory name
  echo "[!] This will delete the following directory and ALL its contents:"
  echo "    $CURRENT_DIR"
  echo "[?] Are you ABSOLUTELY sure? (type 'yes' to confirm)"
  read -r confirm
  
  if [[ "$confirm" == "yes" ]]; then
    cd ..
    rm -rf "$CURRENT_DIR"
    echo "[+] Installation removed"
  else
    echo "[!] Uninstallation cancelled"
  fi
fi

echo "[+] Uninstallation complete" 
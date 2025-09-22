#!/bin/bash

# Installation script for OVPN Importer with NetworkManager Integration

echo "Installing OVPN Importer dependencies..."

# Detect the distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
fi

case $OS in
    "Ubuntu"*|"Debian"*)
        echo "Detected Ubuntu/Debian system"
        sudo apt update
        sudo apt install -y python3-gi gir1.2-gtk-4.0 gir1.2-nm-1.0 network-manager network-manager-openvpn network-manager-openvpn-gnome
        ;;
    "Fedora"*)
        echo "Detected Fedora system"
        sudo dnf install -y python3-gobject gtk4-devel NetworkManager-devel NetworkManager-openvpn NetworkManager-openvpn-gnome
        ;;
    "Arch Linux"*)
        echo "Detected Arch Linux system"
        sudo pacman -S --needed python-gobject gtk4 networkmanager networkmanager-openvpn
        ;;
    *)
        echo "Unsupported distribution: $OS"
        echo "Please install the following packages manually:"
        echo "- python3-gi / python-gobject"
        echo "- gir1.2-gtk-4.0 / gtk4"
        echo "- gir1.2-nm-1.0 / NetworkManager development files"
        echo "- network-manager / NetworkManager"
        echo "- network-manager-openvpn / NetworkManager-openvpn"
        exit 1
        ;;
esac

# Make the script executable
chmod +x ovpn_importer_enhanced.py

echo "Installation completed!"
echo ""
echo "To run the application:"
echo "  python3 ovpn_importer_enhanced.py"
echo ""
echo "Make sure NetworkManager service is running:"
echo "  sudo systemctl enable --now NetworkManager"
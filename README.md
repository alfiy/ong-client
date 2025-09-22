# OVPN Importer with NetworkManager Integration

A GTK4-based application that can parse OpenVPN configuration files (.ovpn) and directly create NetworkManager VPN profiles using the libnm API.

## Features

- **Parse OpenVPN Configuration**: Extracts server details, authentication settings, certificates, and other configuration parameters from .ovpn files
- **NetworkManager Integration**: Uses libnm API to create VPN profiles that integrate directly with the system's network management
- **One-Click Import**: Automatically maps parsed configuration to NetworkManager VPN settings
- **GTK4 Interface**: Modern, user-friendly interface built with GTK4
- **Comprehensive Parsing**: Supports various OpenVPN configuration options including:
  - Remote servers and connection details
  - Certificate-based authentication (CA, cert, key, tls-auth)
  - Username/password authentication
  - Encryption settings (cipher, auth)
  - Compression and routing options

## System Requirements

### Ubuntu/Debian
```bash
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-nm-1.0 network-manager network-manager-openvpn network-manager-openvpn-gnome
```

### Fedora
```bash
sudo dnf install python3-gobject gtk4-devel NetworkManager-devel NetworkManager-openvpn NetworkManager-openvpn-gnome
```

### Arch Linux
```bash
sudo pacman -S python-gobject gtk4 networkmanager networkmanager-openvpn
```

## Usage

1. **Run the application**:
   ```bash
   python3 ovpn_importer_enhanced.py
   ```

2. **Import OpenVPN configuration**:
   - Click "Import .ovpn File" button
   - Select your OpenVPN configuration file
   - The application will parse and display the configuration details

3. **Create VPN Profile**:
   - Enter a name for your VPN connection
   - Click "Create NetworkManager VPN Profile"
   - The VPN profile will be added to your system's network settings

4. **Connect to VPN**:
   - Open your system's network settings
   - Find the newly created VPN connection
   - Connect using your system's network manager

## Configuration Support

The application supports parsing and mapping the following OpenVPN configuration directives:

- `remote` - Server address, port, and protocol
- `proto` - Connection protocol (UDP/TCP)
- `port` - Server port
- `dev` - Virtual network device type (tun/tap)
- `ca` - Certificate Authority file
- `cert` - Client certificate file
- `key` - Private key file
- `tls-auth` - TLS authentication key
- `auth-user-pass` - Username/password authentication
- `cipher` - Encryption cipher
- `auth` - HMAC authentication algorithm
- `comp-lzo` - LZO compression
- `redirect-gateway` - Route all traffic through VPN
- `dhcp-option` - DHCP options

## File Structure

The application expects certificate files referenced in the .ovpn file to be in the same directory as the configuration file, or uses absolute paths if specified.

## Permissions

The application requires appropriate permissions to create NetworkManager connections. On most systems, this is handled automatically through PolicyKit, but you may need to authenticate when creating the VPN profile.

## Troubleshooting

1. **"NetworkManager not available"**: Ensure NetworkManager service is running:
   ```bash
   sudo systemctl status NetworkManager
   ```

2. **Missing GObject introspection libraries**: Install the required GI packages for your distribution

3. **OpenVPN plugin not found**: Install NetworkManager OpenVPN plugin:
   ```bash
   # Ubuntu/Debian
   sudo apt install network-manager-openvpn
   
   # Fedora
   sudo dnf install NetworkManager-openvpn
   ```

4. **Permission denied**: The application uses PolicyKit for authentication. Make sure your user has the necessary permissions to modify network connections.

## Technical Details

- **GUI Framework**: GTK4 with Python GObject bindings
- **NetworkManager API**: Uses libnm (NetworkManager library) through GObject introspection
- **VPN Type**: Creates OpenVPN connections with service type `org.freedesktop.NetworkManager.openvpn`
- **Configuration Mapping**: Automatically maps OpenVPN directives to NetworkManager VPN data properties

## Limitations

- Currently supports OpenVPN configurations only
- Inline certificates (embedded in .ovpn files) are not yet supported - certificates must be in separate files
- Some advanced OpenVPN options may not be mapped to NetworkManager equivalents

## License

This project is provided as-is for educational and practical use. Please ensure you have the right to import and use any VPN configurations.

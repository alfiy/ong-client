#!/usr/bin/env python3
# openvpn_gui_libnm_fixed.py
# GTK4 + libnm minimal prototype that actually adds an OpenVPN profile to NetworkManager.

import sys
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("NM", "1.0")
from gi.repository import Gtk, Gio, NM, GLib

class OpenVPNWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="OpenVPN GUI (libnm)")
        self.set_default_size(480, 300)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                      margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        self.set_child(box)

        self.entry_server = Gtk.Entry(placeholder_text="Server (e.g. vpn.example.com)")
        self.entry_port = Gtk.Entry(placeholder_text="Port (e.g. 1194)")
        self.entry_username = Gtk.Entry(placeholder_text="Username (optional)")
        self.entry_password = Gtk.Entry(placeholder_text="Password (optional)")
        self.entry_password.set_visibility(False)

        box.append(self.entry_server)
        box.append(self.entry_port)
        box.append(self.entry_username)
        box.append(self.entry_password)

        btn = Gtk.Button(label="Create VPN Connection")
        btn.connect("clicked", self.on_create_clicked)
        box.append(btn)

        self.log = Gtk.Label(label="")
        self.log.set_halign(Gtk.Align.START)
        box.append(self.log)

        # init NM client (synchronous - okay for prototype)
        try:
            self.nm_client = NM.Client.new(None)
            self.log.set_text("Connected to NetworkManager")
        except Exception as e:
            self.nm_client = None
            self.log.set_text(f"Failed to init NM client: {e}")

    def append_log(self, text):
        cur = self.log.get_text()
        self.log.set_text((cur + "\n" + text).strip())

    def on_create_clicked(self, button):
        server = self.entry_server.get_text().strip()
        port = self.entry_port.get_text().strip() or "1194"
        username = self.entry_username.get_text().strip()
        password = self.entry_password.get_text()

        if not server:
            self.append_log("Server is required.")
            return

        if not self.nm_client:
            self.append_log("NetworkManager client not available.")
            return

        # Build a minimal SimpleConnection with Connection, IP4 and VPN settings.
        conn = NM.SimpleConnection.new()

        # Connection setting
        s_con = NM.SettingConnection.new()
        s_con.set_property("id", f"OpenVPN {server}")
        s_con.set_property("type", "vpn")
        s_con.set_property("autoconnect", False)
        conn.add_setting(s_con)

        # IPv4 setting (must be present)
        s_ip4 = NM.SettingIP4Config.new()
        s_ip4.set_property("method", "auto")
        conn.add_setting(s_ip4)

        # VPN setting: use SettingVpn (注意是 SettingVpn)
        s_vpn = NM.SettingVpn.new()
        # service-type tells NM which plugin to use (network-manager-openvpn plugin)
        s_vpn.set_property("service-type", "org.freedesktop.NetworkManager.openvpn")
        # add plugin-specific data items:
        s_vpn.add_data_item("remote", server)
        s_vpn.add_data_item("port", str(port))
        # plugin expects username under a key — many plugins use 'username' or 'user-name'
        if username:
            s_vpn.add_data_item("username", username)
        # add secret (may or may not be persisted depending on backend and policy agent)
        if password:
            s_vpn.add_secret("password", password)

        conn.add_setting(s_vpn)

        # Async call to add connection (will trigger polkit if needed)
        def on_add_finished(client, result, user_data):
            try:
                new_conn = client.add_connection_finish(result)
                self.append_log(f"Connection added: id='{new_conn.get_id()}', path={new_conn.get_path()}")
            except GLib.Error as err:
                self.append_log(f"Failed to add connection: {err.message}")

        # save_to_disk=True so it becomes persistent
        try:
            self.nm_client.add_connection_async(conn, True, None, on_add_finished, None)
            self.append_log("Request to add connection sent to NetworkManager...")
        except Exception as e:
            self.append_log(f"Error calling add_connection_async: {e}")


class OpenVPNApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.example.OpenVPNProtoNM")

    def do_activate(self):
        win = OpenVPNWindow(self)
        win.present()

    def do_startup(self):
        Gtk.Application.do_startup(self)

def main():
    app = OpenVPNApp()
    return app.run(sys.argv)

if __name__ == "__main__":
    main()

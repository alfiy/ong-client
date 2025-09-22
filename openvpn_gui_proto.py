#!/usr/bin/env python3
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Gio


class OpenVPNWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="OpenVPN Client ")
        self.set_default_size(400, 250)

        # 主容器
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=20, margin_bottom=20,
                      margin_start=20, margin_end=20)
        self.set_child(box)

        # 输入字段
        self.entry_server = Gtk.Entry(placeholder_text="Server address (e.g. vpn.example.com)")
        self.entry_port = Gtk.Entry(placeholder_text="Port (e.g. 1194)")
        self.entry_username = Gtk.Entry(placeholder_text="Username")
        self.entry_password = Gtk.Entry(placeholder_text="Password")
        self.entry_password.set_visibility(False)

        # 添加到容器
        box.append(self.entry_server)
        box.append(self.entry_port)
        box.append(self.entry_username)
        box.append(self.entry_password)

        # 按钮
        btn = Gtk.Button(label="Create VPN Connection")
        btn.connect("clicked", self.on_create_clicked)
        box.append(btn)

    def on_create_clicked(self, button):
        server = self.entry_server.get_text().strip()
        port = self.entry_port.get_text().strip()
        user = self.entry_username.get_text().strip()
        pwd = self.entry_password.get_text()

        print("=== VPN Config ===")
        print(f"Server: {server}")
        print(f"Port: {port}")
        print(f"Username: {user}")
        print(f"Password: {'*' * len(pwd)}")  # 不直接输出密码


class OpenVPNApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.example.OpenVPNProto",
                         flags=Gio.ApplicationFlags.FLAGS_NONE)

    def do_activate(self):
        win = OpenVPNWindow(self)
        win.present()


if __name__ == "__main__":
    app = OpenVPNApp()
    app.run()


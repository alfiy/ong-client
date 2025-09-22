#!/usr/bin/env python3
import gi
import os

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Gio


class OVPNImporter(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.example.OVPNImporter")

    def do_activate(self):
        # 主窗口
        self.window = Gtk.ApplicationWindow(application=self, title="OVPN Importer")
        self.window.set_default_size(640, 480)

        # 主布局
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        vbox.set_margin_top(12)
        vbox.set_margin_bottom(12)
        vbox.set_margin_start(12)
        vbox.set_margin_end(12)
        self.window.set_child(vbox)

        # 导入按钮
        self.import_button = Gtk.Button(label="Import .ovpn")
        self.import_button.connect("clicked", self.on_import_clicked)
        vbox.append(self.import_button)

        # 状态标签
        self.status = Gtk.Label(label="No file imported yet.")
        vbox.append(self.status)

        # 解析结果展示区（Gtk.TextView）
        self.result_view = Gtk.TextView()
        self.result_view.set_editable(False)
        self.result_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.result_view)
        scrolled.set_vexpand(True)
        vbox.append(scrolled)

        self.window.present()

    def on_import_clicked(self, button):
        dialog = Gtk.FileChooserDialog(
            title="Select .ovpn file",
            transient_for=self.window,
            modal=True,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(
            "_Cancel", Gtk.ResponseType.CANCEL,
            "_Open", Gtk.ResponseType.ACCEPT,
        )

        # 文件过滤器
        filter_ovpn = Gtk.FileFilter()
        filter_ovpn.set_name("OpenVPN config")
        filter_ovpn.add_pattern("*.ovpn")
        dialog.add_filter(filter_ovpn)

        # GTK4: 使用 response 回调，而不是 run()
        dialog.connect("response", self.on_file_chosen)
        dialog.show()

    def on_file_chosen(self, dialog, response_id):
        if response_id == Gtk.ResponseType.ACCEPT:
            gfile = dialog.get_file()
            if gfile:
                path = gfile.get_path()
                if path:
                    parsed = self.parse_ovpn(path)
                    self.status.set_text(f"Imported: {os.path.basename(path)}")
                    self.show_parsed_results(parsed)
        dialog.destroy()

    def parse_ovpn(self, filepath):
        """简单解析 OVPN 文件（示例：提取 remote/proto/port/dev）"""
        results = {"remote": [], "proto": None, "port": None, "dev": None}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("remote "):
                        results["remote"].append(line.split(maxsplit=1)[1])
                    elif line.startswith("proto "):
                        results["proto"] = line.split(maxsplit=1)[1]
                    elif line.startswith("port "):
                        results["port"] = line.split(maxsplit=1)[1]
                    elif line.startswith("dev "):
                        results["dev"] = line.split(maxsplit=1)[1]
        except Exception as e:
            print(f"Failed to parse {filepath}: {e}")
        return results

    def show_parsed_results(self, parsed):
        """在 TextView 中显示解析结果"""
        buffer = self.result_view.get_buffer()
        buffer.set_text("")  # 清空旧内容

        lines = []
        if parsed["remote"]:
            lines.append("Remote servers:")
            for r in parsed["remote"]:
                lines.append(f"  - {r}")
        if parsed["proto"]:
            lines.append(f"Protocol: {parsed['proto']}")
        if parsed["port"]:
            lines.append(f"Port: {parsed['port']}")
        if parsed["dev"]:
            lines.append(f"Device: {parsed['dev']}")

        if not lines:
            lines.append("No recognizable fields found in .ovpn file.")

        buffer.set_text("\n".join(lines))


if __name__ == "__main__":
    app = OVPNImporter()
    app.run()

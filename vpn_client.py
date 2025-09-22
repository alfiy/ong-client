#!/usr/bin/env python3
import gi
import os
import uuid
import logging
import socket
import subprocess

gi.require_version("Gtk", "4.0")
gi.require_version("NM", "1.0")
from gi.repository import Gtk, Gio, NM, GLib

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/ovpn_importer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class OVPNImporter(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.example.OVPNImporter")
        self.nm_client = None
        self.created_connection = None
        self.existing_vpn_connections = []
        self.connection_failed = False

    def do_activate(self):
        # 初始化 NetworkManager 客户端
        self.nm_client = NM.Client.new(None)
        logger.info("NetworkManager client initialized")
        
        # 主窗口
        self.window = Gtk.ApplicationWindow(application=self, title="OVPN Importer with NetworkManager")
        self.window.set_default_size(800, 800)

        # 主布局
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        vbox.set_margin_top(12)
        vbox.set_margin_bottom(12)
        vbox.set_margin_start(12)
        vbox.set_margin_end(12)
        self.window.set_child(vbox)

        # 导入和刷新按钮区域 - 放在一列
        import_refresh_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.import_button = Gtk.Button(label="Import .ovpn File")
        self.import_button.connect("clicked", self.on_import_clicked)
        self.refresh_button = Gtk.Button(label="Refresh VPN List")
        self.refresh_button.connect("clicked", self.on_refresh_vpn_list_clicked)
        import_refresh_box.append(self.import_button)
        import_refresh_box.append(self.refresh_button)
        vbox.append(import_refresh_box)

        # 状态标签
        self.status = Gtk.Label(label="No file imported yet.")
        vbox.append(self.status)

        # 通知标签 (用于显示成功/错误信息)
        self.notification = Gtk.Label(label="")
        self.notification.set_wrap(True)
        self.notification.set_visible(False)
        vbox.append(self.notification)

        # 现有VPN连接管理区域
        existing_frame = Gtk.Frame(label="Existing VPN Connections")
        existing_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        existing_box.set_margin_top(5)
        existing_box.set_margin_bottom(5)
        existing_box.set_margin_start(5)
        existing_box.set_margin_end(5)
        
        # VPN连接数量标签
        self.vpn_count_label = Gtk.Label(label="No VPN connections found")
        existing_box.append(self.vpn_count_label)
        
        # VPN连接列表
        self.vpn_list_box = Gtk.ListBox()
        self.vpn_list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.vpn_list_box.connect("row-selected", self.on_vpn_row_selected)
        
        vpn_scrolled = Gtk.ScrolledWindow()
        vpn_scrolled.set_child(self.vpn_list_box)
        vpn_scrolled.set_vexpand(True)
        vpn_scrolled.set_size_request(-1, 150)
        existing_box.append(vpn_scrolled)
        
        # VPN管理按钮 - 放在一列
        vpn_button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.connect_existing_button = Gtk.Button(label="Connect Selected VPN")
        self.connect_existing_button.connect("clicked", self.on_connect_existing_vpn_clicked)
        self.connect_existing_button.set_sensitive(False)
        
        self.disconnect_vpn_button = Gtk.Button(label="Disconnect VPN")
        self.disconnect_vpn_button.connect("clicked", self.on_disconnect_vpn_clicked)
        self.disconnect_vpn_button.set_sensitive(False)
        
        self.delete_vpn_button = Gtk.Button(label="Delete Selected VPN")
        self.delete_vpn_button.connect("clicked", self.on_delete_vpn_clicked)
        self.delete_vpn_button.set_sensitive(False)
        
        vpn_button_box.append(self.connect_existing_button)
        vpn_button_box.append(self.disconnect_vpn_button)
        vpn_button_box.append(self.delete_vpn_button)
        existing_box.append(vpn_button_box)
        
        existing_frame.set_child(existing_box)
        vbox.append(existing_frame)

        # VPN 连接状态标签
        self.connection_status = Gtk.Label(label="VPN Status: Disconnected")
        vbox.append(self.connection_status)

        # 连接名称输入
        name_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        name_label = Gtk.Label(label="VPN Connection Name:")
        self.name_entry = Gtk.Entry()
        self.name_entry.set_placeholder_text("Enter connection name...")
        name_box.append(name_label)
        name_box.append(self.name_entry)
        vbox.append(name_box)

        # 用户名和密码输入框（用于需要认证的VPN）
        auth_frame = Gtk.Frame(label="Authentication (if required)")
        auth_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        auth_box.set_margin_top(5)
        auth_box.set_margin_bottom(5)
        auth_box.set_margin_start(5)
        auth_box.set_margin_end(5)
        
        username_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        username_label = Gtk.Label(label="Username:")
        username_label.set_size_request(80, -1)
        self.username_entry = Gtk.Entry()
        self.username_entry.set_placeholder_text("VPN username (optional)")
        username_box.append(username_label)
        username_box.append(self.username_entry)
        
        password_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        password_label = Gtk.Label(label="Password:")
        password_label.set_size_request(80, -1)
        self.password_entry = Gtk.Entry()
        self.password_entry.set_placeholder_text("VPN password (optional)")
        self.password_entry.set_visibility(False)  # 隐藏密码
        password_box.append(password_label)
        password_box.append(self.password_entry)
        
        auth_box.append(username_box)
        auth_box.append(password_box)
        auth_frame.set_child(auth_box)
        vbox.append(auth_frame)

        # 按钮容器
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        
        # 测试连接按钮 - 只在连接失败时显示
        self.test_button = Gtk.Button(label="Test Server Connection")
        self.test_button.connect("clicked", self.on_test_connection_clicked)
        self.test_button.set_visible(False)  # 初始隐藏
        button_box.append(self.test_button)
        
        # 连接 VPN 按钮
        self.connect_vpn_button = Gtk.Button(label="Connect to VPN")
        self.connect_vpn_button.connect("clicked", self.on_connect_vpn_clicked)
        self.connect_vpn_button.set_sensitive(False)  # 初始禁用
        button_box.append(self.connect_vpn_button)
        
        vbox.append(button_box)

        # OpenVPN Configuration Analysis - 放在最下面
        analysis_frame = Gtk.Frame(label="OpenVPN Configuration Analysis")
        analysis_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        analysis_box.set_margin_top(5)
        analysis_box.set_margin_bottom(5)
        analysis_box.set_margin_start(5)
        analysis_box.set_margin_end(5)

        self.result_view = Gtk.TextView()
        self.result_view.set_editable(False)
        self.result_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.result_view)
        scrolled.set_vexpand(True)
        scrolled.set_size_request(-1, 200)
        analysis_box.append(scrolled)
        analysis_frame.set_child(analysis_box)
        vbox.append(analysis_frame)

        # 存储解析结果
        self.parsed_config = None
        self.ovpn_file_path = None
        self.active_connection = None
        self.selected_vpn_connection = None

        # 初始化时加载现有VPN连接
        self.load_existing_vpn_connections()

        self.window.present()

    def load_existing_vpn_connections(self):
        """加载现有的VPN连接"""
        try:
            self.existing_vpn_connections = []
            connections = self.nm_client.get_connections()
            
            for conn in connections:
                if conn.get_connection_type() == "vpn":
                    vpn_setting = conn.get_setting_vpn()
                    if vpn_setting and vpn_setting.get_service_type() == "org.freedesktop.NetworkManager.openvpn":
                        self.existing_vpn_connections.append(conn)
                        logger.debug(f"Found existing OpenVPN connection: {conn.get_id()}")
            
            self.update_vpn_list_display()
            logger.info(f"Found {len(self.existing_vpn_connections)} existing VPN connections")
            
        except Exception as e:
            logger.error(f"Error loading existing VPN connections: {e}")
            self.show_error_notification(f"Error loading VPN connections: {str(e)}")

    def update_vpn_list_display(self):
        """更新VPN连接列表显示"""
        # 清空现有列表
        while True:
            row = self.vpn_list_box.get_first_child()
            if row is None:
                break
            self.vpn_list_box.remove(row)
        
        # 更新计数标签
        count = len(self.existing_vpn_connections)
        if count == 0:
            self.vpn_count_label.set_text("No VPN connections found")
        else:
            self.vpn_count_label.set_text(f"Found {count} VPN connection(s)")
        
        # 添加VPN连接到列表
        for conn in self.existing_vpn_connections:
            row = self.create_vpn_list_row(conn)
            self.vpn_list_box.append(row)

    def create_vpn_list_row(self, connection):
        """创建VPN连接列表行"""
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_top(5)
        box.set_margin_bottom(5)
        box.set_margin_start(10)
        box.set_margin_end(10)
        
        # VPN连接名称
        name_label = Gtk.Label(label=connection.get_id())
        name_label.set_halign(Gtk.Align.START)
        name_label.set_hexpand(True)
        
        # VPN服务器信息
        vpn_setting = connection.get_setting_vpn()
        server_info = "Unknown server"
        if vpn_setting:
            remote = vpn_setting.get_data_item("remote")
            port = vpn_setting.get_data_item("port")
            if remote:
                server_info = f"{remote}"
                if port:
                    server_info += f":{port}"
        
        server_label = Gtk.Label(label=server_info)
        server_label.set_halign(Gtk.Align.END)
        server_label.add_css_class("dim-label")
        
        # 连接状态
        status_label = Gtk.Label()
        if self.is_connection_active(connection):
            status_label.set_text("🟢 Connected")
        else:
            status_label.set_text("⚪ Disconnected")
        
        box.append(name_label)
        box.append(server_label)
        box.append(status_label)
        
        # 存储连接对象到行数据中
        box.connection = connection
        
        return box

    def is_connection_active(self, connection):
        """检查连接是否处于活动状态"""
        try:
            active_connections = self.nm_client.get_active_connections()
            for active_conn in active_connections:
                if active_conn.get_connection() == connection:
                    return active_conn.get_state() == NM.ActiveConnectionState.ACTIVATED
            return False
        except Exception as e:
            logger.error(f"Error checking connection status: {e}")
            return False

    def on_refresh_vpn_list_clicked(self, button):
        """刷新VPN连接列表"""
        logger.info("Refreshing VPN connection list")
        self.load_existing_vpn_connections()
        self.show_success_notification("VPN connection list refreshed")

    def on_vpn_row_selected(self, listbox, row):
        """VPN连接行被选中"""
        if row is not None:
            box = row.get_child()
            if hasattr(box, 'connection'):
                self.selected_vpn_connection = box.connection
                logger.info(f"Selected VPN connection: {self.selected_vpn_connection.get_id()}")
                
                # 启用相关按钮
                self.connect_existing_button.set_sensitive(True)
                self.delete_vpn_button.set_sensitive(True)
                
                # 如果连接已激活，启用断开按钮
                if self.is_connection_active(self.selected_vpn_connection):
                    self.disconnect_vpn_button.set_sensitive(True)
                    self.connect_existing_button.set_sensitive(False)
                else:
                    self.disconnect_vpn_button.set_sensitive(False)
                    self.connect_existing_button.set_sensitive(True)
        else:
            self.selected_vpn_connection = None
            self.connect_existing_button.set_sensitive(False)
            self.delete_vpn_button.set_sensitive(False)

    def on_connect_existing_vpn_clicked(self, button):
        """连接选中的现有VPN"""
        if not self.selected_vpn_connection:
            self.show_error_notification("No VPN connection selected")
            return
        
        logger.info(f"Connecting to existing VPN: {self.selected_vpn_connection.get_id()}")
        
        try:
            self.show_success_notification("Connecting to VPN...")
            self.connection_status.set_text("VPN Status: Connecting...")
            
            # 使用选中的连接
            self.created_connection = self.selected_vpn_connection
            self.activate_vpn_connection()
            
        except Exception as e:
            logger.error(f"Error connecting to existing VPN: {str(e)}")
            self.show_error_notification(f"Error connecting to VPN: {str(e)}")
            self.connection_status.set_text("VPN Status: Connection failed")

    def on_delete_vpn_clicked(self, button):
        """删除选中的VPN连接"""
        if not self.selected_vpn_connection:
            self.show_error_notification("No VPN connection selected")
            return
        
        connection_name = self.selected_vpn_connection.get_id()
        
        # 创建确认对话框 - 使用GTK4兼容的方式
        try:
            # 尝试使用 AlertDialog (GTK 4.10+)
            dialog = Gtk.AlertDialog()
            dialog.set_message("Delete VPN Connection")
            dialog.set_detail(f"Are you sure you want to delete the VPN connection '{connection_name}'?\n\nThis action cannot be undone.")
            dialog.set_buttons(["Cancel", "Delete"])
            dialog.set_cancel_button(0)
            dialog.set_default_button(1)
            
            def on_response(dialog, result):
                try:
                    button_index = dialog.choose_finish(result)
                    if button_index == 1:  # Delete button
                        self.delete_vpn_connection(self.selected_vpn_connection)
                except Exception as e:
                    logger.error(f"Error in delete dialog response: {e}")
            
            dialog.choose(self.window, None, on_response)
            
        except Exception as e:
            logger.warning(f"AlertDialog not available: {e}, falling back to MessageDialog")
            # 回退到 MessageDialog
            dialog = Gtk.MessageDialog(
                transient_for=self.window,
                modal=True,
                message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.YES_NO,
                text=f"Delete VPN Connection '{connection_name}'?"
            )
            
            # 使用 set_property 而不是 format_secondary_text
            try:
                dialog.set_property("secondary-text", "Are you sure you want to delete this VPN connection?\n\nThis action cannot be undone.")
            except:
                # 如果 secondary-text 属性不可用，直接在主文本中包含详细信息
                dialog.set_property("text", f"Delete VPN Connection '{connection_name}'?\n\nAre you sure you want to delete this VPN connection?\n\nThis action cannot be undone.")
            
            def on_response(dialog, response_id):
                if response_id == Gtk.ResponseType.YES:
                    self.delete_vpn_connection(self.selected_vpn_connection)
                dialog.destroy()
            
            dialog.connect("response", on_response)
            dialog.present()

    def delete_vpn_connection(self, connection):
        """删除VPN连接"""
        try:
            connection_name = connection.get_id()
            logger.info(f"Deleting VPN connection: {connection_name}")
            
            def delete_cb(connection, result, user_data):
                try:
                    success = connection.delete_finish(result)
                    if success:
                        logger.info(f"Successfully deleted VPN connection: {connection_name}")
                        self.show_success_notification(f"VPN connection '{connection_name}' deleted successfully")
                        # 刷新列表
                        self.load_existing_vpn_connections()
                        # 清除选择
                        self.selected_vpn_connection = None
                        self.connect_existing_button.set_sensitive(False)
                        self.delete_vpn_button.set_sensitive(False)
                    else:
                        logger.error("Failed to delete VPN connection")
                        self.show_error_notification("Failed to delete VPN connection")
                except Exception as e:
                    logger.error(f"Error in delete callback: {e}")
                    self.show_error_notification(f"Error deleting VPN connection: {str(e)}")
            
            connection.delete_async(None, delete_cb, None)
            
        except Exception as e:
            logger.error(f"Error deleting VPN connection: {e}")
            self.show_error_notification(f"Error deleting VPN connection: {str(e)}")

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
        dialog.present()

    def on_file_chosen(self, dialog, response_id):
        if response_id == Gtk.ResponseType.ACCEPT:
            gfile = dialog.get_file()
            if gfile:
                path = gfile.get_path()
                if path:
                    logger.info(f"Selected OVPN file: {path}")
                    self.ovpn_file_path = path
                    parsed = self.parse_ovpn(path)
                    self.parsed_config = parsed
                    self.status.set_text(f"Imported: {os.path.basename(path)}")
                    self.show_parsed_results(parsed)
                    
                    # 自动填充连接名称
                    base_name = os.path.splitext(os.path.basename(path))[0]
                    self.name_entry.set_text(base_name)
                    
                    # 验证并创建VPN连接
                    if self.validate_certificates():
                        connection_name = self.name_entry.get_text().strip()
                        if connection_name:
                            success = self.create_nm_vpn_connection(connection_name, self.parsed_config)
                            if success:
                                self.show_success_notification(f"VPN connection '{connection_name}' created successfully!")
                                # 启用连接按钮
                                self.connect_vpn_button.set_sensitive(True)
                                # 自动刷新VPN列表
                                self.load_existing_vpn_connections()
                            else:
                                self.show_error_notification("Failed to create VPN connection")
                    
                    # 清除之前的通知
                    self.hide_notification()
        dialog.destroy()

    def parse_ovpn(self, filepath):
        """增强的 OVPN 文件解析，提取更多配置信息"""
        logger.info(f"Parsing OVPN file: {filepath}")
        results = {
            "remote": [],
            "proto": "udp",  # 默认值
            "port": "1194",  # 默认值
            "dev": "tun",    # 默认值
            "ca": None,
            "cert": None,
            "key": None,
            "tls_auth": None,
            "tls_crypt": None,  # 新增 tls-crypt 支持
            "tls_crypt_v2": None,  # 新增 tls-crypt-v2 支持
            "auth_user_pass": False,
            "cipher": None,
            "auth": None,
            "comp_lzo": False,
            "verb": None,
            "mute": None,
            "route_delay": None,
            "redirect_gateway": False,
            "dhcp_option": [],
            "raw_config": "",
            "inline_ca": None,
            "inline_cert": None,
            "inline_key": None,
            "inline_tls_auth": None,
            "inline_tls_crypt": None,
            "inline_tls_crypt_v2": None,
            "tls_version_min": None,
            "remote_cert_tls": None,
            "key_direction": None
        }
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                results["raw_config"] = content
                
                # 处理内联证书和密钥
                content = self.extract_inline_certificates(content, results)
                
                for line in content.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    parts = line.split()
                    if not parts:
                        continue
                        
                    cmd = parts[0].lower()
                    
                    if cmd == "remote" and len(parts) >= 2:
                        server = parts[1]
                        port = parts[2] if len(parts) > 2 else "1194"
                        proto = parts[3] if len(parts) > 3 else "udp"
                        results["remote"].append({"server": server, "port": port, "proto": proto})
                        logger.debug(f"Found remote server: {server}:{port} ({proto})")
                    elif cmd == "proto" and len(parts) > 1:
                        results["proto"] = parts[1]
                    elif cmd == "port" and len(parts) > 1:
                        results["port"] = parts[1]
                    elif cmd == "dev" and len(parts) > 1:
                        results["dev"] = parts[1]
                    elif cmd == "ca" and len(parts) > 1:
                        results["ca"] = parts[1]
                        logger.debug(f"Found CA file reference: {parts[1]}")
                    elif cmd == "cert" and len(parts) > 1:
                        results["cert"] = parts[1]
                        logger.debug(f"Found cert file reference: {parts[1]}")
                    elif cmd == "key" and len(parts) > 1:
                        results["key"] = parts[1]
                        logger.debug(f"Found key file reference: {parts[1]}")
                    elif cmd == "tls-auth" and len(parts) > 1:
                        results["tls_auth"] = parts[1]
                        if len(parts) > 2:
                            results["key_direction"] = parts[2]
                        logger.debug(f"Found tls-auth file reference: {parts[1]}")
                    elif cmd == "tls-crypt" and len(parts) > 1:
                        results["tls_crypt"] = parts[1]
                        logger.debug(f"Found tls-crypt file reference: {parts[1]}")
                    elif cmd == "tls-crypt-v2" and len(parts) > 1:
                        results["tls_crypt_v2"] = parts[1]
                        logger.debug(f"Found tls-crypt-v2 file reference: {parts[1]}")
                    elif cmd == "auth-user-pass":
                        results["auth_user_pass"] = True
                        logger.debug("Found auth-user-pass directive")
                    elif cmd == "cipher" and len(parts) > 1:
                        results["cipher"] = parts[1]
                    elif cmd == "auth" and len(parts) > 1:
                        results["auth"] = parts[1]
                    elif cmd == "comp-lzo":
                        results["comp_lzo"] = True
                    elif cmd == "redirect-gateway":
                        results["redirect_gateway"] = True
                    elif cmd == "dhcp-option" and len(parts) > 1:
                        results["dhcp_option"].append(" ".join(parts[1:]))
                    elif cmd == "verb" and len(parts) > 1:
                        results["verb"] = parts[1]
                    elif cmd == "tls-version-min" and len(parts) > 1:
                        results["tls_version_min"] = parts[1]
                    elif cmd == "remote-cert-tls" and len(parts) > 1:
                        results["remote_cert_tls"] = parts[1]
                    elif cmd == "key-direction" and len(parts) > 1:
                        results["key_direction"] = parts[1]
                        
        except Exception as e:
            logger.error(f"Failed to parse {filepath}: {e}")
            
        return results

    def extract_inline_certificates(self, content, results):
        """提取内联证书并保存为临时文件"""
        import tempfile
        import re
        
        # 提取内联CA证书
        ca_match = re.search(r'<ca>(.*?)</ca>', content, re.DOTALL)
        if ca_match:
            ca_content = ca_match.group(1).strip()
            ca_file = tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False)
            ca_file.write(ca_content)
            ca_file.close()
            results["inline_ca"] = ca_file.name
            results["ca"] = ca_file.name
            logger.info(f"Extracted inline CA certificate to: {ca_file.name}")
            content = re.sub(r'<ca>.*?</ca>', '', content, flags=re.DOTALL)
        
        # 提取内联客户端证书
        cert_match = re.search(r'<cert>(.*?)</cert>', content, re.DOTALL)
        if cert_match:
            cert_content = cert_match.group(1).strip()
            cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False)
            cert_file.write(cert_content)
            cert_file.close()
            results["inline_cert"] = cert_file.name
            results["cert"] = cert_file.name
            logger.info(f"Extracted inline client certificate to: {cert_file.name}")
            content = re.sub(r'<cert>.*?</cert>', '', content, flags=re.DOTALL)
        
        # 提取内联私钥
        key_match = re.search(r'<key>(.*?)</key>', content, re.DOTALL)
        if key_match:
            key_content = key_match.group(1).strip()
            key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
            key_file.write(key_content)
            key_file.close()
            results["inline_key"] = key_file.name
            results["key"] = key_file.name
            logger.info(f"Extracted inline private key to: {key_file.name}")
            content = re.sub(r'<key>.*?</key>', '', content, flags=re.DOTALL)
        
        # 提取内联TLS认证密钥
        tls_auth_match = re.search(r'<tls-auth>(.*?)</tls-auth>', content, re.DOTALL)
        if tls_auth_match:
            tls_auth_content = tls_auth_match.group(1).strip()
            tls_auth_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
            tls_auth_file.write(tls_auth_content)
            tls_auth_file.close()
            results["inline_tls_auth"] = tls_auth_file.name
            results["tls_auth"] = tls_auth_file.name
            logger.info(f"Extracted inline TLS auth key to: {tls_auth_file.name}")
            content = re.sub(r'<tls-auth>.*?</tls-auth>', '', content, flags=re.DOTALL)
        
        # 提取内联TLS-Crypt密钥
        tls_crypt_match = re.search(r'<tls-crypt>(.*?)</tls-crypt>', content, re.DOTALL)
        if tls_crypt_match:
            tls_crypt_content = tls_crypt_match.group(1).strip()
            tls_crypt_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
            tls_crypt_file.write(tls_crypt_content)
            tls_crypt_file.close()
            results["inline_tls_crypt"] = tls_crypt_file.name
            results["tls_crypt"] = tls_crypt_file.name
            logger.info(f"Extracted inline TLS-Crypt key to: {tls_crypt_file.name}")
            content = re.sub(r'<tls-crypt>.*?</tls-crypt>', '', content, flags=re.DOTALL)
        
        # 提取内联TLS-Crypt-v2密钥
        tls_crypt_v2_match = re.search(r'<tls-crypt-v2>(.*?)</tls-crypt-v2>', content, re.DOTALL)
        if tls_crypt_v2_match:
            tls_crypt_v2_content = tls_crypt_v2_match.group(1).strip()
            tls_crypt_v2_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
            tls_crypt_v2_file.write(tls_crypt_v2_content)
            tls_crypt_v2_file.close()
            results["inline_tls_crypt_v2"] = tls_crypt_v2_file.name
            results["tls_crypt_v2"] = tls_crypt_v2_file.name
            logger.info(f"Extracted inline TLS-Crypt-v2 key to: {tls_crypt_v2_file.name}")
            content = re.sub(r'<tls-crypt-v2>.*?</tls-crypt-v2>', '', content, flags=re.DOTALL)
        
        return content

    def on_test_connection_clicked(self, button):
        """测试VPN服务器连接"""
        if not self.parsed_config or not self.parsed_config["remote"]:
            self.show_error_notification("No server configuration found")
            return
            
        remote = self.parsed_config["remote"][0]
        server = remote["server"]
        port = int(remote["port"])
        proto = remote["proto"]
        
        logger.info(f"Testing connection to {server}:{port} ({proto})")
        self.show_success_notification(f"Testing connection to {server}:{port}...")
        
        def test_connection():
            try:
                if proto.lower() == "tcp":
                    # TCP连接测试
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    result = sock.connect_ex((server, port))
                    sock.close()
                    if result == 0:
                        GLib.idle_add(self.show_success_notification, f"✅ TCP connection to {server}:{port} successful")
                    else:
                        GLib.idle_add(self.show_error_notification, f"❌ TCP connection to {server}:{port} failed")
                else:
                    # UDP连接测试（发送数据包）
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)
                    try:
                        sock.sendto(b'\x38\x01\x00\x00\x00\x00\x00\x00\x00', (server, port))
                        data, addr = sock.recvfrom(1024)
                        GLib.idle_add(self.show_success_notification, f"✅ UDP connection to {server}:{port} successful")
                    except socket.timeout:
                        GLib.idle_add(self.show_success_notification, f"⚠️ UDP connection to {server}:{port} timeout (server may still be reachable)")
                    except Exception as e:
                        GLib.idle_add(self.show_error_notification, f"❌ UDP connection to {server}:{port} failed: {str(e)}")
                    finally:
                        sock.close()
                        
            except Exception as e:
                logger.error(f"Connection test failed: {e}")
                GLib.idle_add(self.show_error_notification, f"Connection test failed: {str(e)}")
        
        # 在后台线程中运行测试
        import threading
        threading.Thread(target=test_connection, daemon=True).start()

    def show_parsed_results(self, parsed):
        """在 TextView 中显示解析结果"""
        buffer = self.result_view.get_buffer()
        buffer.set_text("")  # 清空旧内容

        lines = []
        lines.append("=== OpenVPN Configuration Analysis ===")
        
        if parsed["remote"]:
            lines.append("\nRemote servers:")
            for r in parsed["remote"]:
                lines.append(f"  - Server: {r['server']}, Port: {r['port']}, Protocol: {r['proto']}")
        
        lines.append(f"\nProtocol: {parsed['proto']}")
        lines.append(f"Port: {parsed['port']}")
        lines.append(f"Device: {parsed['dev']}")
        
        if parsed["ca"]:
            ca_status = "✓ Found" if os.path.exists(parsed["ca"]) else "✗ Missing"
            lines.append(f"CA Certificate: {parsed['ca']} ({ca_status})")
        if parsed["cert"]:
            cert_status = "✓ Found" if os.path.exists(parsed["cert"]) else "✗ Missing"
            lines.append(f"Client Certificate: {parsed['cert']} ({cert_status})")
        if parsed["key"]:
            key_status = "✓ Found" if os.path.exists(parsed["key"]) else "✗ Missing"
            lines.append(f"Private Key: {parsed['key']} ({key_status})")
        if parsed["tls_auth"]:
            tls_status = "✓ Found" if os.path.exists(parsed["tls_auth"]) else "✗ Missing"
            lines.append(f"TLS Auth: {parsed['tls_auth']} ({tls_status})")
        if parsed["tls_crypt"]:
            tls_crypt_status = "✓ Found" if os.path.exists(parsed["tls_crypt"]) else "✗ Missing"
            lines.append(f"TLS Crypt: {parsed['tls_crypt']} ({tls_crypt_status})")
        if parsed["tls_crypt_v2"]:
            tls_crypt_v2_status = "✓ Found" if os.path.exists(parsed["tls_crypt_v2"]) else "✗ Missing"
            lines.append(f"TLS Crypt v2: {parsed['tls_crypt_v2']} ({tls_crypt_v2_status})")
            
        lines.append(f"Username/Password Auth: {'Yes' if parsed['auth_user_pass'] else 'No'}")
        
        if parsed["cipher"]:
            lines.append(f"Cipher: {parsed['cipher']}")
        if parsed["auth"]:
            lines.append(f"Auth Algorithm: {parsed['auth']}")
        if parsed["tls_version_min"]:
            lines.append(f"TLS Version Min: {parsed['tls_version_min']}")
        if parsed["remote_cert_tls"]:
            lines.append(f"Remote Cert TLS: {parsed['remote_cert_tls']}")
        if parsed["key_direction"]:
            lines.append(f"Key Direction: {parsed['key_direction']}")
            
        lines.append(f"LZO Compression: {'Yes' if parsed['comp_lzo'] else 'No'}")
        lines.append(f"Redirect Gateway: {'Yes' if parsed['redirect_gateway'] else 'No'}")
        
        if parsed["dhcp_option"]:
            lines.append("\nDHCP Options:")
            for opt in parsed["dhcp_option"]:
                lines.append(f"  - {opt}")

        if not any([parsed["remote"], parsed["ca"], parsed["cert"]]):
            lines.append("\nWarning: No recognizable OpenVPN fields found in file.")
        else:
            lines.append(f"\n📋 Log file: /tmp/ovpn_importer.log")

        buffer.set_text("\n".join(lines))

    def validate_certificates(self):
        """验证证书文件是否存在"""
        config = self.parsed_config
        missing_files = []
        
        if config["ca"]:
            if not os.path.exists(config["ca"]):
                missing_files.append(f"CA certificate: {config['ca']}")
        else:
            missing_files.append("CA certificate (required)")
            
        if not config["auth_user_pass"]:  # 如果不是用户名密码认证，需要证书
            if config["cert"] and not os.path.exists(config["cert"]):
                missing_files.append(f"Client certificate: {config['cert']}")
            if config["key"] and not os.path.exists(config["key"]):
                missing_files.append(f"Private key: {config['key']}")
        
        if config["tls_auth"] and not os.path.exists(config["tls_auth"]):
            missing_files.append(f"TLS auth key: {config['tls_auth']}")
        
        if config["tls_crypt"] and not os.path.exists(config["tls_crypt"]):
            missing_files.append(f"TLS crypt key: {config['tls_crypt']}")
            
        if config["tls_crypt_v2"] and not os.path.exists(config["tls_crypt_v2"]):
            missing_files.append(f"TLS crypt v2 key: {config['tls_crypt_v2']}")
        
        if missing_files:
            error_msg = "Missing required certificate files:\n" + "\n".join(missing_files)
            logger.error(error_msg)
            self.show_error_notification(error_msg)
            return False
        
        return True

    def create_nm_vpn_connection(self, name, config):
        """使用 libnm API 创建 OpenVPN 连接"""
        try:
            logger.info(f"Creating NetworkManager VPN connection: {name}")
            
            # 创建新的连接设置
            connection = NM.SimpleConnection.new()
            
            # 基本连接设置
            s_con = NM.SettingConnection.new()
            s_con.set_property(NM.SETTING_CONNECTION_ID, name)
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, "vpn")
            s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
            connection.add_setting(s_con)
            
            # VPN 设置
            s_vpn = NM.SettingVpn.new()
            s_vpn.set_property(NM.SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.openvpn")
            
            # 设置 VPN 数据
            vpn_data = {}
            
            # 远程服务器设置
            if config["remote"]:
                remote = config["remote"][0]  # 使用第一个远程服务器
                vpn_data["remote"] = remote["server"]
                vpn_data["port"] = remote["port"]
                vpn_data["proto-tcp"] = "yes" if remote["proto"].lower() == "tcp" else "no"
                logger.debug(f"VPN server: {remote['server']}:{remote['port']} ({remote['proto']})")
            
            # 连接类型
            if config["auth_user_pass"]:
                vpn_data["connection-type"] = "password"
                logger.debug("Using password authentication")
            else:
                vpn_data["connection-type"] = "tls"
                logger.debug("Using TLS certificate authentication")
            
            # 设备类型
            if config["dev"].startswith("tun"):
                vpn_data["dev-type"] = "tun"
            elif config["dev"].startswith("tap"):
                vpn_data["dev-type"] = "tap"
            
            # 证书文件路径处理
            ovpn_dir = os.path.dirname(self.ovpn_file_path)
            
            if config["ca"]:
                ca_path = config["ca"]
                if not os.path.isabs(ca_path):
                    ca_path = os.path.join(ovpn_dir, ca_path)
                vpn_data["ca"] = ca_path
                logger.debug(f"CA certificate path: {ca_path}")
            
            if config["cert"]:
                cert_path = config["cert"]
                if not os.path.isabs(cert_path):
                    cert_path = os.path.join(ovpn_dir, cert_path)
                vpn_data["cert"] = cert_path
                logger.debug(f"Client certificate path: {cert_path}")
            
            if config["key"]:
                key_path = config["key"]
                if not os.path.isabs(key_path):
                    key_path = os.path.join(ovpn_dir, key_path)
                vpn_data["key"] = key_path
                logger.debug(f"Private key path: {key_path}")
            
            # TLS 认证设置 - 关键修复点
            if config["tls_auth"]:
                tls_auth_path = config["tls_auth"]
                if not os.path.isabs(tls_auth_path):
                    tls_auth_path = os.path.join(ovpn_dir, tls_auth_path)
                vpn_data["tls-auth"] = tls_auth_path
                if config["key_direction"]:
                    vpn_data["key-direction"] = config["key_direction"]
                logger.debug(f"TLS auth key path: {tls_auth_path}")
            
            # TLS-Crypt 设置 - 新增支持
            if config["tls_crypt"]:
                tls_crypt_path = config["tls_crypt"]
                if not os.path.isabs(tls_crypt_path):
                    tls_crypt_path = os.path.join(ovpn_dir, tls_crypt_path)
                vpn_data["tls-crypt"] = tls_crypt_path
                logger.debug(f"TLS crypt key path: {tls_crypt_path}")
            
            # TLS-Crypt-v2 设置 - 新增支持
            if config["tls_crypt_v2"]:
                tls_crypt_v2_path = config["tls_crypt_v2"]
                if not os.path.isabs(tls_crypt_v2_path):
                    tls_crypt_v2_path = os.path.join(ovpn_dir, tls_crypt_v2_path)
                vpn_data["tls-crypt-v2"] = tls_crypt_v2_path
                logger.debug(f"TLS crypt v2 key path: {tls_crypt_v2_path}")
            
            # 加密设置
            if config["cipher"]:
                vpn_data["cipher"] = config["cipher"]
            
            if config["auth"]:
                vpn_data["auth"] = config["auth"]
            
            # TLS设置
            if config["tls_version_min"]:
                vpn_data["tls-version-min"] = config["tls_version_min"]
                
            if config["remote_cert_tls"]:
                vpn_data["remote-cert-tls"] = config["remote_cert_tls"]
            
            # 压缩设置
            if config["comp_lzo"]:
                vpn_data["comp-lzo"] = "yes"
            
            # 其他设置
            if config["redirect_gateway"]:
                vpn_data["redirect-gateway"] = "yes"
            
            # 添加超时设置以避免TLS握手超时
            vpn_data["connect-timeout"] = "120"
            vpn_data["ping"] = "10"
            vpn_data["ping-restart"] = "60"
            
            # 记录所有VPN数据
            logger.debug("VPN configuration data:")
            for key, value in vpn_data.items():
                logger.debug(f"  {key}: {value}")
            
            # 设置 VPN 数据
            for key, value in vpn_data.items():
                s_vpn.add_data_item(key, value)
            
            # 如果需要用户名密码认证，设置密钥标志
            if config["auth_user_pass"]:
                s_vpn.add_secret("password", "")  # 空密码，稍后用户输入
                
            connection.add_setting(s_vpn)
            
            # IP 设置 (IPv4)
            s_ip4 = NM.SettingIP4Config.new()
            s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
            connection.add_setting(s_ip4)
            
            # IP 设置 (IPv6)
            s_ip6 = NM.SettingIP6Config.new()
            s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
            connection.add_setting(s_ip6)
            
            # 添加连接到 NetworkManager
            def add_connection_cb(client, result, user_data):
                try:
                    new_con = client.add_connection_finish(result)
                    if new_con:
                        logger.info(f"Successfully added VPN connection: {name}")
                        self.created_connection = new_con
                        return True
                    else:
                        logger.error("Failed to add VPN connection")
                        return False
                except Exception as e:
                    logger.error(f"Error adding connection: {e}")
                    return False
            
            self.nm_client.add_connection_async(connection, True, None, add_connection_cb, None)
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating NetworkManager VPN connection: {e}")
            return False

    def on_connect_vpn_clicked(self, button):
        """连接到VPN服务器"""
        if not self.created_connection and not self.find_existing_connection():
            self.show_error_notification("No VPN connection available. Please create one first.")
            return
        
        connection_name = self.name_entry.get_text().strip()
        username = self.username_entry.get_text().strip()
        password = self.password_entry.get_text().strip()
        
        logger.info(f"Attempting to connect to VPN: {connection_name}")
        
        try:
            self.show_success_notification("Connecting to VPN...")
            self.connection_status.set_text("VPN Status: Connecting...")
            
            # 如果需要用户名密码认证
            if self.parsed_config and self.parsed_config.get("auth_user_pass", False):
                if not username:
                    self.show_error_notification("Username is required for this VPN connection")
                    self.connection_status.set_text("VPN Status: Connection failed")
                    return
                
                logger.debug(f"Using username: {username}")
                # 更新连接的密钥
                self.update_connection_secrets(username, password)
            
            # 激活连接
            self.activate_vpn_connection()
            
        except Exception as e:
            logger.error(f"Error connecting to VPN: {str(e)}")
            self.show_error_notification(f"Error connecting to VPN: {str(e)}")
            self.connection_status.set_text("VPN Status: Connection failed")

    def find_existing_connection(self):
        """查找已存在的VPN连接"""
        connection_name = self.name_entry.get_text().strip()
        if not connection_name:
            return False
            
        connections = self.nm_client.get_connections()
        for conn in connections:
            if conn.get_id() == connection_name and conn.get_connection_type() == "vpn":
                self.created_connection = conn
                logger.info(f"Found existing VPN connection: {connection_name}")
                return True
        return False

    def update_connection_secrets(self, username, password):
        """更新连接的用户名和密码"""
        if not self.created_connection:
            return
            
        try:
            # 获取VPN设置
            vpn_setting = self.created_connection.get_setting_vpn()
            if vpn_setting:
                # 设置用户名
                vpn_setting.add_data_item("username", username)
                if password:
                    vpn_setting.add_secret("password", password)
                logger.debug("Updated connection credentials")
                    
        except Exception as e:
            logger.error(f"Error updating connection secrets: {e}")

    def activate_vpn_connection(self):
        """激活VPN连接"""
        if not self.created_connection:
            return
            
        def activation_cb(client, result, user_data):
            try:
                active_conn = client.activate_connection_finish(result)
                if active_conn:
                    self.active_connection = active_conn
                    logger.info("VPN connection activated successfully")
                    self.show_success_notification("VPN connected successfully!")
                    self.connection_status.set_text("VPN Status: Connected")
                    self.connect_vpn_button.set_sensitive(False)
                    self.connect_existing_button.set_sensitive(False)
                    self.disconnect_vpn_button.set_sensitive(True)
                    
                    # 隐藏测试按钮，因为连接成功了
                    self.test_button.set_visible(False)
                    self.connection_failed = False
                    
                    # 刷新VPN列表以更新状态
                    self.update_vpn_list_display()
                    
                    # 监听连接状态变化
                    active_conn.connect("state-changed", self.on_connection_state_changed)
                else:
                    logger.error("Failed to activate VPN connection")
                    self.show_error_notification("Failed to activate VPN connection")
                    self.connection_status.set_text("VPN Status: Connection failed")
                    # 显示测试按钮，因为连接失败了
                    self.test_button.set_visible(True)
                    self.connection_failed = True
            except Exception as e:
                logger.error(f"Error in activation callback: {e}")
                self.show_error_notification(f"VPN connection failed: {str(e)}")
                self.connection_status.set_text("VPN Status: Connection failed")
                # 显示测试按钮，因为连接失败了
                self.test_button.set_visible(True)
                self.connection_failed = True
        
        logger.debug("Activating VPN connection...")
        # 激活连接
        self.nm_client.activate_connection_async(
            self.created_connection, 
            None,  # device (None for VPN)
            None,  # specific_object
            None,  # cancellable
            activation_cb,
            None   # user_data
        )

    def on_connection_state_changed(self, active_conn, state, reason):
        """VPN连接状态变化回调"""
        state_names = {
            0: "UNKNOWN",
            1: "ACTIVATING", 
            2: "ACTIVATED",
            3: "DEACTIVATING",
            4: "DEACTIVATED"
        }
        
        reason_names = {
            0: "UNKNOWN",
            1: "NONE", 
            2: "USER_DISCONNECTED",
            3: "DEVICE_DISCONNECTED",
            4: "SERVICE_STOPPED",
            5: "IP_CONFIG_INVALID",
            6: "CONNECT_TIMEOUT",
            7: "SERVICE_START_TIMEOUT",
            8: "SERVICE_START_FAILED",
            9: "NO_SECRETS",
            10: "LOGIN_FAILED",
            11: "CONNECTION_REMOVED"
        }
        
        state_name = state_names.get(state, f"UNKNOWN({state})")
        reason_name = reason_names.get(reason, f"UNKNOWN({reason})")
        
        logger.debug(f"VPN connection state changed: {state_name} (reason: {reason_name})")
        
        if state == NM.ActiveConnectionState.ACTIVATED:
            self.connection_status.set_text("VPN Status: Connected")
            self.connect_vpn_button.set_sensitive(False)
            self.connect_existing_button.set_sensitive(False)
            self.disconnect_vpn_button.set_sensitive(True)
            self.show_success_notification("VPN connection established!")
            # 隐藏测试按钮，因为连接成功了
            self.test_button.set_visible(False)
            self.connection_failed = False
            # 刷新VPN列表以更新状态
            self.update_vpn_list_display()
        elif state == NM.ActiveConnectionState.DEACTIVATED:
            self.connection_status.set_text("VPN Status: Disconnected")
            self.connect_vpn_button.set_sensitive(True)
            self.connect_existing_button.set_sensitive(True)
            self.disconnect_vpn_button.set_sensitive(False)
            self.active_connection = None
            # 刷新VPN列表以更新状态
            self.update_vpn_list_display()
            if reason == 6:  # CONNECT_TIMEOUT
                self.show_error_notification("VPN connection timeout - check server connectivity")
                self.test_button.set_visible(True)
                self.connection_failed = True
            elif reason == 10:  # LOGIN_FAILED
                self.show_error_notification("VPN login failed - check credentials")
                self.test_button.set_visible(True)
                self.connection_failed = True
            elif reason != 2:  # Not USER_DISCONNECTED
                self.show_error_notification(f"VPN disconnected: {reason_name}")
                self.test_button.set_visible(True)
                self.connection_failed = True
        elif state == NM.ActiveConnectionState.ACTIVATING:
            self.connection_status.set_text("VPN Status: Connecting...")

    def on_disconnect_vpn_clicked(self, button):
        """断开VPN连接"""
        if not self.active_connection:
            self.show_error_notification("No active VPN connection to disconnect")
            return
            
        logger.info("Disconnecting VPN...")
        try:
            def deactivation_cb(client, result, user_data):
                try:
                    success = client.deactivate_connection_finish(result)
                    if success:
                        logger.info("VPN disconnected successfully")
                        self.show_success_notification("VPN disconnected successfully!")
                        self.connection_status.set_text("VPN Status: Disconnected")
                        self.connect_vpn_button.set_sensitive(True)
                        self.connect_existing_button.set_sensitive(True)
                        self.disconnect_vpn_button.set_sensitive(False)
                        self.active_connection = None
                        # 刷新VPN列表以更新状态
                        self.update_vpn_list_display()
                    else:
                        logger.error("Failed to disconnect VPN")
                        self.show_error_notification("Failed to disconnect VPN")
                except Exception as e:
                    logger.error(f"Error in deactivation callback: {e}")
                    self.show_error_notification(f"Error disconnecting VPN: {str(e)}")
            
            self.nm_client.deactivate_connection_async(
                self.active_connection,
                None,  # cancellable
                deactivation_cb,
                None   # user_data
            )
            
        except Exception as e:
            logger.error(f"Error disconnecting VPN: {str(e)}")
            self.show_error_notification(f"Error disconnecting VPN: {str(e)}")

    def show_success_notification(self, message):
        """显示成功通知"""
        self.notification.set_text(f"✅ SUCCESS: {message}")
        self.notification.set_css_classes(["success"])
        self.notification.set_visible(True)
        
        # 5秒后自动隐藏
        GLib.timeout_add_seconds(5, self.hide_notification)

    def show_error_notification(self, message):
        """显示错误通知"""
        self.notification.set_text(f"❌ ERROR: {message}")
        self.notification.set_css_classes(["error"])
        self.notification.set_visible(True)
        
        # 10秒后自动隐藏
        GLib.timeout_add_seconds(10, self.hide_notification)

    def hide_notification(self):
        """隐藏通知"""
        self.notification.set_visible(False)
        return False  # 停止 GLib.timeout


if __name__ == "__main__":
    app = OVPNImporter()
    app.run()
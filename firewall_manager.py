import sys
import os
import re
import platform
import shutil
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QWidget, QMessageBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import QThread, pyqtSignal
import subprocess
import ctypes
import socket

def ensure_admin():
    os_type = get_os_type()
    
    if os_type == 'windows':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit()
    elif os_type in ['linux', 'darwin']:  # macOS
        if os.geteuid() != 0:
            print("Ứng dụng cần quyền quản trị viên.")
            if os_type == 'linux':
                subprocess.run(["pkexec", sys.executable, *sys.argv])
            elif os_type == 'darwin':  # macOS
                command = f'do shell script "{sys.executable} {" ".join(sys.argv)}" with administrator privileges'
                subprocess.run(["osascript", "-e", command])
            sys.exit()

def check_internet_access():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except OSError:
        return False

# Hàm xác định hệ điều hành
def get_os_type():
    """
    Hàm kiểm tra loại hệ điều hành hiện tại.
    """
    from sys import platform
    if platform.startswith("linux"):
        return "linux"
    elif platform == "darwin":
        return "darwin"  # macOS
    elif platform == "win32":
        return "windows"
    else:
        return "unknown"

# Hàm kiểm tra sự tồn tại của lệnh
def check_command_exists(command):
    return shutil.which(command) is not None

# Hàm chặn IP
def block_ip(ip):
    os_type = get_os_type()
    
    if os_type == 'linux':
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
        print(f"IP {ip} đã bị chặn trên Linux.")
        
    elif os_type == 'darwin':  # macOS
        os.system(f'sudo pfctl -f /etc/pf.conf && sudo pfctl -e')
        print(f"IP {ip} đã bị chặn trên macOS. Vui lòng thêm quy tắc vào /etc/pf.conf nếu cần.")
        
    elif os_type == 'windows':
        # Lệnh chặn IP trên Windows
        block_command_out = f'netsh advfirewall firewall add rule dir=out action=block remoteip={ip} name="BlockIP_{ip}"'
        block_command_in = f'netsh advfirewall firewall add rule dir=in action=block remoteip={ip} name="BlockIP_{ip}"'

        os.system(block_command_out)
        os.system(block_command_in)
        print(f"IP {ip} đã bị chặn trên Windows.")
        
    else:
        print(f"Hệ điều hành không xác định. Không thể chặn IP {ip}.")

# Hàm kiểm tra trạng thái tường lửa
def check_firewall_status():
    os_type = get_os_type()
    try:
        if os_type == 'windows':
            # Lấy đầu ra từ lệnh netsh
            status = os.popen('netsh advfirewall show allprofiles').read().lower()
            print(f"Debug Firewall Status Raw Output:\n{status}")  # Debug đầu ra

            # Tìm tất cả các trạng thái "state on"
            for line in status.splitlines():
                if "state" in line and "on" in line:
                    return True  # Tường lửa đang bật
            return False  
        elif os_type == 'linux':
            status = os.popen('ufw status').read().lower()
            return "active" in status
        elif os_type == 'darwin':  # macOS
            status = os.popen('sudo pfctl -s info').read().lower()
            return "status: enabled" in status
        else:
            return False
    except Exception as e:
        print(f"Error in check_firewall_status: {e}")
        return False

# Hàm bật Firewall
def enable_firewall():
    os_type = get_os_type()
    if os_type == 'linux':
        os.system('sudo ufw enable')
    elif os_type == 'darwin':  # macOS
        os.system('sudo pfctl -E')
    elif os_type == 'windows':
        os.system('netsh advfirewall set allprofiles state on')

# Hàm tắt Firewall
def disable_firewall():
    os_type = get_os_type()
    if os_type == 'linux':
        os.system('sudo ufw disable')
    elif os_type == 'darwin':  # macOS
        os.system('sudo pfctl -d')
    elif os_type == 'windows':
        os.system('netsh advfirewall set allprofiles state off')

# Luồng theo dõi log
class LogMonitorThread(QThread):
    log_signal = pyqtSignal(str)  # Tín hiệu để cập nhật log vào UI

    def run(self):
        os_type = get_os_type()
        if os_type == 'linux':
            log_command = 'sudo tail -f /var/log/syslog'
        elif os_type == 'darwin':  # macOS
            log_command = 'sudo tail -f /var/log/system.log'
        elif os_type == 'windows':
            log_command = 'wevtutil qe System /f:text /c:50'
        else:
            self.log_signal.emit("Hệ điều hành không được hỗ trợ để theo dõi log.")
            return

        process = os.popen(log_command)
        blocked_ips = set()
        while True:
            log_line = process.readline()
            if log_line:
                self.log_signal.emit(log_line.strip())
                suspicious_ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', log_line)
                for ip in suspicious_ips:
                    if ip not in blocked_ips:
                        block_ip(ip)
                        blocked_ips.add(ip)
                        self.log_signal.emit(f"Đã chặn IP: {ip}")
            time.sleep(1)

# Giao diện chính
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Manager")
        self.resize(1000, 800)

        # Layout chính
        layout = QVBoxLayout()

        # Khu vực trạng thái Firewall
        self.firewall_status_label = QLabel("Trạng thái Firewall: Đang kiểm tra...")
        layout.addWidget(self.firewall_status_label)
        self.update_firewall_status()

        # Nút bật/tắt Firewall
        firewall_control_layout = QHBoxLayout()
        self.enable_firewall_button = QPushButton("Bật Firewall")
        self.enable_firewall_button.clicked.connect(self.enable_firewall)
        self.disable_firewall_button = QPushButton("Tắt Firewall")
        self.disable_firewall_button.clicked.connect(self.disable_firewall)
        firewall_control_layout.addWidget(self.enable_firewall_button)
        firewall_control_layout.addWidget(self.disable_firewall_button)
        layout.addLayout(firewall_control_layout)

        # Khu vực log
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log_display)

        # Nút theo dõi log
        self.start_monitor_button = QPushButton("Bắt đầu theo dõi log")
        self.start_monitor_button.clicked.connect(self.start_monitoring)
        layout.addWidget(self.start_monitor_button)

        # Nút thêm, xóa rule
        rule_layout = QHBoxLayout()
        self.rule_port_input = QLineEdit()
        self.rule_port_input.setPlaceholderText("Nhập port...")
        self.rule_action_input = QLineEdit()
        self.rule_action_input.setPlaceholderText("Nhập hành động (ACCEPT/DROP)...")
        self.add_rule_button = QPushButton("Thêm Rule")
        self.add_rule_button.clicked.connect(self.add_rule)
        self.delete_rule_button = QPushButton("Xóa Rule")
        self.delete_rule_button.clicked.connect(self.delete_rule)
        rule_layout.addWidget(self.rule_port_input)
        rule_layout.addWidget(self.rule_action_input)
        rule_layout.addWidget(self.add_rule_button)
        rule_layout.addWidget(self.delete_rule_button)
        layout.addLayout(rule_layout)

        # Bảng hiển thị rule
        self.rules_table = QTableWidget(0, 3)
        self.rules_table.setHorizontalHeaderLabels(["Số thứ tự", "Chi tiết Rule", "Hành động"])
        layout.addWidget(QLabel("Danh sách Rules:"))
        layout.addWidget(self.rules_table)

        # Nút cập nhật rule
        self.update_rules_button = QPushButton("Cập nhật Rules")
        self.update_rules_button.clicked.connect(self.update_rules)
        layout.addWidget(self.update_rules_button)

        # Nút tải hướng dẫn
        self.download_guide_button = QPushButton("Tải hướng dẫn cấu hình Firewall")
        self.download_guide_button.clicked.connect(self.download_guide)
        layout.addWidget(self.download_guide_button)

        # Khu vực hiển thị syslog
        self.syslog_display = QTextEdit()
        self.syslog_display.setReadOnly(True)
        layout.addWidget(QLabel("Syslog:"))
        layout.addWidget(self.syslog_display)

        # Nút hiển thị syslog
        self.show_syslog_button = QPushButton("Hiển thị Syslog")
        self.show_syslog_button.clicked.connect(self.show_syslog)
        layout.addWidget(self.show_syslog_button)

        # Widget tổng
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Luồng theo dõi log
        self.log_thread = LogMonitorThread()
        self.log_thread.log_signal.connect(self.update_log)

        # Cập nhật trạng thái ban đầu
        self.update_firewall_status()

    def update_firewall_status(self):
        status = check_firewall_status()
        print(f"Firewall status: {status}")
        if status:
            self.firewall_status_label.setText("Trạng thái Firewall: Đã bật")
        else:
            self.firewall_status_label.setText("Trạng thái Firewall: Đã tắt")

    def enable_firewall(self):
        enable_firewall()
        QMessageBox.information(self, "Thành công", "Đã bật Firewall.")
        self.update_firewall_status()

    def disable_firewall(self):
        disable_firewall()
        QMessageBox.information(self, "Thành công", "Đã tắt Firewall.")
        self.update_firewall_status()

    def start_monitoring(self):
        if not self.log_thread.isRunning():
            self.log_thread.start()
            self.log_display.append("Đang theo dõi log...")

    def update_log(self, log_line):
        self.log_display.append(log_line)

    def add_rule(self):
        port = self.rule_port_input.text()
        action = self.rule_action_input.text()
        if not port or not action:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập đầy đủ port và hành động.")
            return

        os_type = get_os_type()
        if os_type == 'linux':
            os.system(f'sudo iptables -A INPUT -p tcp --dport {port} -j {action}')
        elif os_type == 'darwin':  # macOS
            rule = f"pass in proto tcp from any to any port {port}\n"
            os.system(f"echo '{rule}' | sudo tee -a /etc/pf.conf > /dev/null")
            os.system("sudo pfctl -f /etc/pf.conf && sudo pfctl -e")
        elif os_type == 'windows':
            os.system(f'netsh advfirewall firewall add rule name="Rule_{port}_{action}" dir=in action={action} protocol=TCP localport={port}')
            os.system(f'netsh advfirewall firewall add rule name="Rule_{port}_{action}" dir=out action={action} protocol=TCP localport={port}')
        else:
            QMessageBox.warning(self, "Lỗi", "Hệ điều hành không hỗ trợ thêm rule.")

        QMessageBox.information(self, "Thành công", f"Đã thêm rule: {action} port {port}.")
        self.update_rules()

    def delete_rule(self):
        row = self.rules_table.currentRow()
        if row == -1:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn rule để xóa.")
            return

        rule_number = self.rules_table.item(row, 0).text()
        os_type = get_os_type()
        if os_type == 'linux':
            os.system(f'sudo iptables -D INPUT {rule_number}')
        elif os_type == 'darwin':  # macOS
            os.system(f"sudo pfctl -F all")
        elif os_type == 'windows':
            os.system(f'netsh advfirewall firewall delete rule name="{rule_number}"')
        else:
            QMessageBox.warning(self, "Lỗi", "Hệ điều hành không hỗ trợ xóa rule.")

        QMessageBox.information(self, "Thành công", f"Đã xóa rule số {rule_number}.")
        self.update_rules()

    def update_rules(self):
        os_type = get_os_type()
        rules = []
        if os_type == 'linux':
            rules = os.popen('sudo iptables -L -v -n --line-numbers').readlines()
        elif os_type == 'darwin':  # macOS
            rules = os.popen('sudo pfctl -sr').readlines()
        elif os_type == 'windows':
            rules = os.popen('netsh advfirewall firewall show rule name=all').readlines()

        self.rules_table.setRowCount(0)
        for i, rule in enumerate(rules):
            self.rules_table.insertRow(i)
            self.rules_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.rules_table.setItem(i, 1, QTableWidgetItem(rule.strip()))
            self.rules_table.setItem(i, 2, QTableWidgetItem("ACCEPT/DROP"))

    def download_guide(self):
        guide_content = """
        Hướng dẫn cấu hình firewall:
        1. Thêm Rule: iptables -A INPUT -p tcp --dport [port] -j ACCEPT/DROP
        2. Giới hạn băng thông: Yêu cầu 'tc'
        3. Lọc theo dải IP: iptables -A INPUT -s [IP range] -j ACCEPT/DROP
        """
        with open("firewall_guide.txt", "w") as f:
            f.write(guide_content)
        QMessageBox.information(self, "Thành công", "Hướng dẫn đã được tải xuống.")

    def show_syslog(self):
        os_type = get_os_type()
        logs = ""
        
        if os_type == 'linux':
            logs = os.popen('sudo tail -n 50 /var/log/syslog').read()
        elif os_type == 'darwin':  # macOS
            logs = os.popen('sudo tail -n 50 /var/log/system.log').read()
        elif os_type == 'windows':
            # Lệnh PowerShell để lấy các sự kiện hệ thống gần đây
            logs = os.popen('powershell Get-EventLog -LogName System -Newest 50').read()
        
        self.syslog_display.setText(logs)

if __name__ == "__main__":
    ensure_admin()  # Đảm bảo chạy với quyền Admin
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
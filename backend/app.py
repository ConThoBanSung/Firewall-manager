from flask import Flask, request, jsonify, send_file
import os
import re
import platform
import shutil
from flask_cors import CORS
from io import BytesIO
import threading
import time

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

def monitor_logs():
    os_type = get_os_type()
    blocked_ips = set()  # Dùng set để tránh chặn IP nhiều lần
    if os_type == 'linux':
        log_command = 'sudo tail -f /var/log/syslog'
    elif os_type == 'darwin':  # macOS
        log_command = 'sudo tail -f /var/log/system.log'
    elif os_type == 'windows':
        return  # Windows không hỗ trợ theo dõi log tương tự
    else:
        return  # Không xác định hệ điều hành
    
    # Theo dõi log theo thời gian thực
    process = os.popen(log_command)
    while True:
        log_line = process.readline()
        if log_line:
            # Tìm IP trong log
            suspicious_ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', log_line)
            for ip in suspicious_ips:
                if ip not in blocked_ips:
                    print(f"Chặn IP nghi ngờ: {ip}")
                    block_ip(ip)
                    blocked_ips.add(ip)
        time.sleep(1)

# Hàm chặn IP
def block_ip(ip):
    os_type = get_os_type()
    if os_type == 'linux':
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
    elif os_type == 'darwin':  # macOS
        os.system(f'sudo pfctl -f /etc/pf.conf && sudo pfctl -e')  # Cập nhật lại pf.conf
    elif os_type == 'windows':
        print(f"Windows không hỗ trợ iptables. Không thể chặn IP {ip}.")
    else:
        print(f"Hệ điều hành không xác định. Không thể chặn IP {ip}.")

# Hàm để xác định hệ điều hành
def get_os_type():
    os_type = platform.system().lower()
    return os_type

# Hàm kiểm tra sự tồn tại của lệnh
def check_command_exists(command):
    return shutil.which(command) is not None

# Hàm cấp quyền cho tệp (Linux, macOS)
def ensure_permissions():
    os_type = get_os_type()
    if os_type == 'linux':
        os.system("sudo chmod u+w /etc/iptables/rules.v4")  # Cấp quyền cho tệp iptables trên Linux
    elif os_type == 'darwin':  # macOS
        os.system("sudo chmod u+w /etc/pf.conf")  # Cấp quyền cho tệp pf.conf trên macOS

# API cấu hình firewall hiện đại (ví dụ: Thêm rule cho băng thông, dịch vụ, hoặc địa chỉ IP)
@app.route('/configure_firewall', methods=['POST'])
def configure_firewall():
    os_type = get_os_type()
    data = request.json
    port = data.get('port')
    action = data.get('action')  # ACCEPT hoặc DROP
    bandwidth_limit = data.get('bandwidth_limit')  # Giới hạn băng thông (kbps)
    ip_range = data.get('ip_range')  # Dải IP (nếu có)
    service_name = data.get('service_name')  # Tên dịch vụ (nếu có)

    ensure_permissions()  # Đảm bảo rằng các tệp có quyền cần thiết

    # Cấu hình firewall với các tính năng hiện đại (bandwidth limit, service filtering, IP filtering)
    if os_type == 'linux':
        if check_command_exists('iptables'):
            # Ví dụ: Lọc băng thông (bandwidth)
            if bandwidth_limit:
                os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
                # Cấu hình băng thông nếu cần thiết (Giới hạn băng thông có thể yêu cầu thêm các công cụ khác như `tc` hoặc `iptables -m limit`)
            # Thêm IP range hoặc service filtering nếu có
            if ip_range:
                os.system(f"sudo iptables -A INPUT -s {ip_range} -p tcp --dport {port} -j {action}")
            if service_name:
                os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -m string --algo bm --hex-string '|{service_name}|'" + f" -j {action}")
        else:
            return jsonify({"message": "iptables chưa được cài đặt."})
    
    elif os_type == 'darwin':  # macOS
        if check_command_exists("pfctl"):
            # Cấu hình pfctl với các tính năng hiện đại (giới hạn băng thông, dịch vụ, hoặc IP)
            if ip_range:
                rule = f"pass in proto tcp from {ip_range} to any port {port}\n"
                os.system(f"echo '{rule}' | sudo tee -a /etc/pf.conf > /dev/null")
            if service_name:
                rule = f"pass in proto tcp from any to any port {port} keep state\n"
                os.system(f"echo '{rule}' | sudo tee -a /etc/pf.conf > /dev/null")
            os.system("sudo pfctl -f /etc/pf.conf && sudo pfctl -e")  # Nạp lại cấu hình pf
        else:
            return jsonify({"message": "pfctl chưa được cài đặt. Vui lòng cài đặt nó."})
    
    elif os_type == 'windows':
        return jsonify({"message": "Windows không hỗ trợ iptables."})
    
    return jsonify({"message": "Firewall configured successfully."})

# API tải tệp hướng dẫn cấu hình firewall về máy của client
@app.route('/download_guide', methods=['GET'])
def download_guide():
    guide_content = """
    Hướng dẫn cấu hình firewall:

    1. Thêm một quy tắc:
        - Chạy lệnh: iptables -A INPUT -p tcp --dport [port] -j ACCEPT/DROP
    2. Giới hạn băng thông:
        - Cấu hình băng thông yêu cầu công cụ 'tc' (Traffic Control).
    3. Lọc theo dải IP:
        - iptables -A INPUT -s [IP range] -p tcp --dport [port] -j ACCEPT/DROP
    4. Lọc theo dịch vụ:
        - iptables -A INPUT -p tcp --dport [port] -m string --algo bm --hex-string '|[service_name]|' -j ACCEPT/DROP
    """

    # Tạo một file hướng dẫn tạm thời
    guide_file = BytesIO()
    guide_file.write(guide_content.encode('utf-8'))
    guide_file.seek(0)

    return send_file(guide_file, as_attachment=True, download_name="firewall_config_guide.txt", mimetype="text/plain")

# API lấy các rule hiện tại
@app.route('/rules', methods=['GET'])
def get_rules():
    os_type = get_os_type()
    rules = ""
    
    if os_type == 'linux':
        if check_command_exists('iptables'):
            rules = os.popen('sudo iptables -L -v -n --line-numbers').read()
        else:
            rules = "iptables chưa được cài đặt."
    
    elif os_type == 'darwin':  # macOS
        if check_command_exists("pfctl"):
            rules = os.popen('sudo pfctl -sr').read()  
        else:
            rules = "pfctl không có sẵn trên hệ thống này."
    
    elif os_type == 'windows':
        rules = "Windows không hỗ trợ iptables."
    else:
        rules = "Hệ điều hành không xác định."
    
    return jsonify({"rules": rules})

# API thêm rule mới
@app.route('/add_rule', methods=['POST'])
def add_rule():
    os_type = get_os_type()
    data = request.json
    port = data.get('port')
    action = data.get('action')  # ACCEPT hoặc DROP

    ensure_permissions()  # Đảm bảo rằng các tệp có quyền cần thiết

    if os_type == 'linux':
        if check_command_exists('iptables'):
            os.system(f'sudo iptables -A INPUT -p tcp --dport {port} -j {action}')
        else:
            return jsonify({"message": "iptables chưa được cài đặt."})
    
    elif os_type == 'darwin':  # macOS
        if check_command_exists("pfctl"):
            # Thêm quy tắc vào pf.conf thông qua lệnh sudo
            rule = f"pass in proto tcp from any to any port {port}\n"
            os.system(f"echo '{rule}' | sudo tee -a /etc/pf.conf > /dev/null")
            os.system("sudo pfctl -f /etc/pf.conf && sudo pfctl -e")  # Nạp lại cấu hình pf
        else:
            return jsonify({"message": "pfctl chưa được cài đặt. Vui lòng cài đặt nó."})
    
    elif os_type == 'windows':
        return jsonify({"message": "Windows không hỗ trợ iptables."})
    
    return jsonify({"message": f"Rule added: {action} port {port}"})

# API xóa rule
@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    os_type = get_os_type()
    data = request.json
    rule_number = data.get('rule_number')
    
    ensure_permissions()  # Đảm bảo rằng các tệp có quyền cần thiết

    if os_type == 'linux':
        if check_command_exists('iptables'):
            os.system(f'sudo iptables -D INPUT {rule_number}')
        else:
            return jsonify({"message": "iptables chưa được cài đặt."})
    
    elif os_type == 'darwin':  # macOS
        if check_command_exists("pfctl"):
            os.system(f"sudo pfctl -F all")  # Xóa tất cả các quy tắc
            os.system("sudo pfctl -e")  # Kích hoạt lại pf
        else:
            return jsonify({"message": "pfctl chưa được cài đặt. Vui lòng cài đặt nó."})
    
    elif os_type == 'windows':
        return jsonify({"message": "Windows không hỗ trợ iptables."})

    return jsonify({"message": f"Rule {rule_number} deleted"})

# API lấy log mạng
@app.route('/logs', methods=['GET'])
def get_logs():
    os_type = get_os_type()
    
    if os_type == 'linux':
        if check_command_exists('dmesg'):
            logs = os.popen('sudo dmesg | tail -n 50').read()
        else:
            logs = "dmesg không có sẵn trên hệ thống này."
    
    elif os_type == 'darwin':  # macOS
        logs = os.popen('sudo tail -n 50 /var/log/system.log').read()
    elif os_type == 'windows':
        logs = "Windows không có dmesg."
    else:
        logs = "Hệ điều hành không xác định."

    return jsonify({"logs": logs})

# API lấy syslog
@app.route('/syslog', methods=['GET'])
def get_syslog():
    os_type = get_os_type()

    if os_type == 'linux':
        logs = os.popen('sudo tail -n 50 /var/log/syslog').read()
    elif os_type == 'darwin':  # macOS
        logs = os.popen('sudo tail -n 50 /var/log/system.log').read()
    elif os_type == 'windows':
        logs = "Windows không có syslog."
    else:
        logs = "Hệ điều hành không xác định."
    
    return jsonify({"logs": logs})

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    # Chạy thread theo dõi log
    monitor_thread = threading.Thread(target=monitor_logs)
    monitor_thread.daemon = True  # Cho phép thread tự kết thúc khi ứng dụng dừng
    monitor_thread.start()
    
    return jsonify({"message": "Đang theo dõi log và chặn IP nghi ngờ trong thời gian thực."})

@app.route('/block_suspicious_ips', methods=['POST'])
def block_suspicious_ips():
    # Đang thực thi monitor logs trong nền
    return jsonify({"message": "IP nghi ngờ sẽ tự động bị chặn khi phát hiện."})



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)

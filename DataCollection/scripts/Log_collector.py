import os
import subprocess
import json
import psutil
import platform
import win32evtlog
import sys
import ctypes


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def run_as_admin():
    if not is_admin():
        script = sys.argv[0]
        params = " ".join(sys.argv[1:])
        command = f'python "{script}" {params}'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, command, None, 1)
        # sys.exit(0)


def get_system_logs_windows():
    try:
        server = 'localhost'
        log_type = 'System'
        hand = win32evtlog.OpenEventLog(server, log_type)
        events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_FORWARDS_READ, 0)

        logs = []
        while events:
            for event in events:
                logs.append({
                    "TimeGenerated": event.TimeGenerated,
                    "EventID": event.EventID,
                    "SourceName": event.SourceName,
                    "Message": event.Message
                })
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_FORWARDS_READ, 0)

        return logs
    except Exception as e:
        print(f"Error reading system logs: {e}")
        return []


def get_network_logs():
    try:
        command = ["C:\\Program Files\\Wireshark\\tshark.exe", "-D"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.decode('utf-8')
    except Exception as e:
        print(f"Error capturing network logs: {e}")
        return []


def get_firewall_logs_windows():
    firewall_log_path = "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
    if os.path.exists(firewall_log_path):
        try:
            with open(firewall_log_path, 'r') as f:
                return f.readlines()
        except PermissionError:
            print("Permission error while reading the firewall log.")
            return []
    else:
        print(f"Firewall log not found at {firewall_log_path}")
        return []


def get_application_logs():
    logs = []
    apache_log_path = "C:\\Apache24\\logs\\access.log"
    if os.path.exists(apache_log_path):
        try:
            with open(apache_log_path, 'r') as f:
                logs.extend(f.readlines())
        except Exception as e:
            print(f"Error reading Apache logs: {e}")
    
    if platform.system() == "Linux":
        apache_log_path = "/var/log/apache2/access.log"
        if os.path.exists(apache_log_path):
            try:
                with open(apache_log_path, 'r') as f:
                    logs.extend(f.readlines())
            except Exception as e:
                print(f"Error reading Apache logs on Linux: {e}")
    
    return logs


def get_process_logs():
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            processes.append(f"PID: {proc.info['pid']} Name: {proc.info['name']}")
        return processes
    except Exception as e:
        print(f"Error reading process logs: {e}")
        return []


def get_antivirus_logs():
    try:
        command = ["powershell", "Get-MpEvent"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.decode('utf-8')
    except Exception as e:
        print(f"Error getting antivirus logs: {e}")
        return []


def get_security_logs():
    try:
        result = subprocess.run(["powershell", "Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 }"], capture_output=True, text=True, check=True)
        logs = result.stdout.strip().splitlines()
        return logs
    except subprocess.CalledProcessError as e:
        print(f"Error getting security logs: {e}")
        return []


def collect_logs():
    logs = {}

    if platform.system() == "Windows":
        logs["System Logs"] = get_system_logs_windows()

    logs["Network Logs"] = get_network_logs()

    logs["Firewall Logs"] = get_firewall_logs_windows()

    logs["Application Logs"] = get_application_logs()

    logs["Process Logs"] = get_process_logs()

    logs["Antivirus Logs"] = get_antivirus_logs()

    logs["Security Logs"] = get_security_logs()

    return logs


if __name__ == "__main__":
    run_as_admin()

    collected_logs = collect_logs()
    with open('data_collected\logs_data\collected_logs.json', 'w') as f:
        json.dump(collected_logs, f, indent=4)
    
    print("Logs collected and saved to 'data_collected/logs_data/collected_logs.json'.")



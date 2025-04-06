import os
import subprocess
import shutil
import ctypes
import sys
import logging
import datetime
from dotenv import load_dotenv 

load_dotenv()

LOGS_DIR = os.getenv('LOGS_DIR')

logging.basicConfig(
    filename="C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/IDS logging info/log_extraction.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def create_logs_directory():
    """Create a directory to store the logs."""
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
        print(f"Logs directory created at: {LOGS_DIR}")
        logging.info("Logs directory created.")
    else:
        print(f"Logs directory already exists at: {LOGS_DIR}")
        logging.info("Logs directory already exists.")

def is_admin():
        """Check if the script is running with administrative privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logging.error(f"Error checking admin privileges: {e}")
            return False

def run_as_admin():
    """Relaunch the script with admin privileges if not already."""
    if not is_admin():
        print("Requesting admin privileges...")
        logging.info("Requesting admin privileges...")
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            # sys.exit(0)
        except Exception as e:
            logging.error(f"Failed to relaunch as admin: {e}")
            print("Failed to gain admin privileges. Exiting.")
            sys.exit(1)


def save_to_file(filename, content, format='txt'):
    """Save content to a file in the specified format."""
    filepath = os.path.join(LOGS_DIR, filename)
    
    if format == 'json':
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(content, file, indent=4)
    elif format == 'csv':
        df = pd.DataFrame(content)
        df.to_csv(filepath, index=False)
    else:
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(content)
    
    print(f"Saved: {filepath}")
    logging.info(f"Saved log to {filepath}")

def get_event_logs(log_type):
    """Extract Windows Event Logs."""
    print(f"Extracting {log_type} Event Logs...")
    logging.info(f"Extracting {log_type} Event Logs...")
    command = f"wevtutil qe {log_type} /f:text"
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        save_to_file(f"{log_type}_event_logs.txt", output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to extract {log_type} logs: {e}")
        print(f"Failed to extract {log_type} logs: {e}")

def grant_access_to_firewall_log():
    """Grant the script access to the pfirewall.log file by modifying its permissions."""
    command = 'icacls "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log" /grant %username%:F'
    try:
        subprocess.check_call(command, shell=True)
        print("Permissions granted to access firewall log.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to grant permissions: {e}")

def get_network_connections():
    """Extract active network connections."""
    print("Extracting network connections...")
    logging.info("Extracting network connections...")
    command = "netstat -ano"
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        save_to_file("network_connections.txt", output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to extract network connections: {e}")
        print(f"Failed to extract network connections: {e}")

def get_running_processes():
    """Extract the list of running processes."""
    print("Extracting running processes...")
    logging.info("Extracting running processes...")
    command = "tasklist"
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        save_to_file("running_processes.txt", output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to extract running processes: {e}")
        print(f"Failed to extract running processes: {e}")

def get_security_logs():
    """Extract Security Event Logs using PowerShell."""
    print("Extracting Security Event Logs using PowerShell...")
    command = 'powershell Get-WinEvent -LogName Security -OutFile "ids_logs\\Security_event_logs.psv"'
    try:
        subprocess.check_call(command, shell=True)
        print("Security Event Logs extracted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to extract Security logs: {e}")

def get_open_ports():
    """Extract open ports."""
    print("Extracting open ports...")
    logging.info("Extracting open ports...")
    command = "netsh interface ipv4 show excludedportrange protocol=tcp"
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        save_to_file("open_ports.txt", output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to extract open ports: {e}")
        print(f"Failed to extract open ports: {e}")


def get_firewall_logs():
    """Extract Windows Firewall logs if enabled."""
    print("Checking for firewall logs...")
    logging.info("Checking for firewall logs...")
    firewall_log_path = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    grant_access_to_firewall_log()
    if os.path.exists(firewall_log_path):
        try:
            shutil.copy(firewall_log_path, os.path.join(LOGS_DIR, "firewall_logs.txt"))
            print(f"Firewall logs copied to: {os.path.join(LOGS_DIR, 'firewall_logs.txt')}")
        except Exception as e:
            print(f"Failed to copy firewall logs: {e}")
    else:
        print("No firewall logs found.")



def main():
    """Main function to orchestrate log extraction."""
    print("Starting IDS log extraction...")
    logging.info("Starting IDS log extraction...")
    
    if not is_admin():
        run_as_admin()
    
    create_logs_directory()
    
    for log in ["Application", "System"]:
        get_event_logs(log)
    
    get_network_connections()
    get_running_processes()
    get_open_ports()
    get_firewall_logs()
    
    print("Log extraction complete. All logs are saved in the 'ids_logs' directory.")
    logging.info("Log extraction complete.")

if __name__ == "__main__":
    main()
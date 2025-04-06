from scapy.all import sniff, IP, TCP, UDP
from time import time
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.http import HTTP, HTTPResponse

TIME_WINDOW = timedelta(minutes=1)

# Initialize counters and storage for session data
packet_count = 0
session_data = {}

# Initialize global dictionaries for tracking various metrics
state_ttl_counter = defaultdict(int)  # Track ct_state_ttl
dst_ltm_counter = defaultdict(list)  # Track ct_dst_ltm
src_dport_ltm_counter = defaultdict(list)  # Track ct_src_dport_ltm
dst_sport_ltm_counter = defaultdict(list)  # Track ct_dst_sport_ltm
dst_src_ltm_counter = defaultdict(list)  # Track ct_dst_src_ltm


# Initialize counters for each metric
ftp_login_counter = defaultdict(bool)  # Track whether FTP login has occurred (True/False)
ftp_cmd_counter = defaultdict(int)  # Track count of FTP commands
http_method_counter = defaultdict(int)  # Track count of HTTP method

# Initialize counters and trackers
src_ltm_counter = defaultdict(int)  # Count packets from source IPs within the last minute
srv_dst_counter = defaultdict(set)  # Track distinct destination ports for each source IP
ips_ports_counter = defaultdict(set)  # Track source IPs and source ports
attack_category = defaultdict(str)  # Placeholder for attack category (e.g., 'DoS', 'Probe')
label = defaultdict(str)  # Label the traffic as 'Normal' or 'Attack'

# Define FTP commands and HTTP methods of interest
ftp_commands = {'USER', 'PASS', 'QUIT', 'RETR', 'STOR', 'DELE', 'LIST'}
http_methods = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'}

port_to_service = {
    21: "FTP", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S"
}

def calculate_time_metrics(packet_data):
    """
    Calculate metrics: ct_src_ltm, ct_srv_dst, is_sm_ips_ports, attack_cat, label based on packet data.
    """
    timestamp = packet_data[-1]['timestamp']

    if isinstance(timestamp, float):
        timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    current_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    time_window = timedelta(minutes=1)  # Set a time window of 1 minute

    for packet in packet_data:
        # Convert timestamp string to datetime object
        timestamp = datetime.strptime(packet['timestamp'], '%Y-%m-%d %H:%M:%S')
        
        # ct_src_ltm: Count how many packets from the source IP within the last minute
        if current_time - timestamp <= time_window:
            src_ltm_counter[packet['src_ip']] += 1
        
        # ct_srv_dst: Count distinct destination ports (services) from the same source IP
        srv_dst_counter[packet['src_ip']].add(packet['dst_port'])
        
        # is_sm_ips_ports: Track source IPs and ports, check if there are too many distinct pairs (potential anomaly)
        ips_ports_counter[(packet['src_ip'], packet['src_port'])].add(packet['dst_ip'])
        
        # Attack classification (for simplicity, using a basic check here; in practice, this would be more advanced)
        if packet['protocol'] == 'TCP' and packet['dst_port'] == 443:  # Example: DoS if destination port is 443
            attack_category[packet['src_ip']] = 'DoS'  # Hypothetical attack category
            label[packet['src_ip']] = 'Attack'  # Assign attack label to the source IP
        else:
            attack_category[packet['src_ip']] = 'Normal'
            label[packet['src_ip']] = 'Normal'

    # Calculate is_sm_ips_ports: if there are too many distinct source IPs and ports
    is_small_ips_ports = {}
    for key, ip_ports in ips_ports_counter.items():
        if len(ip_ports) < 5:  # If the number of distinct ports is small, we flag it
            is_small_ips_ports[key] = True
        else:
            is_small_ips_ports[key] = False

    # Print metrics for each source IP
    for ip in src_ltm_counter:
        packet_data['ct_src_ltm'] = src_ltm_counter[ip]
        packet_data['ct_srv_dst'] = len(srv_dst_counter[ip])
        packet_data['is_sm_ips_ports'] = 'Yes' if is_small_ips_ports.get((ip, 80), False) else 'No'
        packet_data['attack_cat'] = attack_category[ip]
        packet_data['label'] = label[ip] 
        print(f"Source IP: {ip}")
        print(f"  ct_src_ltm (packets in the last minute): {src_ltm_counter[ip]}")
        print(f"  ct_srv_dst (distinct services): {len(srv_dst_counter[ip])}")
        print(f"  is_sm_ips_ports: {'Yes' if is_small_ips_ports.get((ip, 80), False) else 'No'}")  # Assuming src port is 80 for this check
        print(f"  Attack Category: {attack_category[ip]}")
        print(f"  Label: {label[ip]}")
        print('-' * 50)
    
    return packet_data
        
def calculate_ftp_metrics(packet_data):
    """
    Calculate FTP metrics: is_ftp_login and ct_ftp_cmd based on packet data.
    """
    for packet in packet_data:
        if packet['protocol'] == 'FTP':
            ftp_cmd = packet['ftp_cmd']  # Get the FTP command from the packet data
            if ftp_cmd in ftp_commands:
                ftp_cmd_counter[ftp_cmd] += 1  # Count the FTP command
                # Check if login has occurred (USER/PASS sequence)
                if ftp_cmd == 'USER' or ftp_cmd == 'PASS':
                    ftp_login_counter[packet['src_ip']] = True  # Mark FTP login as True
    # Print the calculated metrics
    for ip, logged_in in ftp_login_counter.items():
        print(f"FTP login status for {ip}: {'Login Successful' if logged_in else 'Login Not Attempted'}")
        packet_data['ip']['is_ftp_login'] = 1 if logged_in else 0
    
    total_count = 0
    for cmd, count in ftp_cmd_counter.items():
        print(f"FTP command '{cmd}' count: {count}")
        total_count += count
    packet_data['ct_ftp_cmd'] = total_count 


    return packet_data

def calculate_http_metrics(packet_data):
    """
    Calculate HTTP metrics: ct_flw_http_mthd based on packet data.
    """
    for packet in packet_data:
        if packet['protocol'] == 'HTTP':
            http_method = packet['http_method']  # Get the HTTP method from the packet data
            if http_method in http_methods:
                http_method_counter[http_method] += 1  # Count the HTTP method
    # Print the calculated HTTP method counts
    for method, count in http_method_counter.items():
        print(f"HTTP method '{method}' count: {count}")
        packet_data['ct_flw_http_mthd'] += count
    
    return packet_data


def determine_state(packet):
    """Determines the connection state based on TCP flags."""
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if tcp_flags & 0x01:  # FIN flag is set
            return "FIN"
        elif tcp_flags & 0x04:  # RST flag is set
            return "INT"
        elif tcp_flags & 0x02 or tcp_flags & 0x10:  # SYN or ACK flags set
            return "CON"
    return "UNKNOWN"

# this function is only calculating i have to add it to dictionary ...abs
# 
# 
def calculate_time_window_counts(packet_data):
    # Calculate ct_dst_ltm for destination IP over time
    for dst_ip, timestamps in dst_ltm_counter.items():
        timestamps.sort()  # Sort the timestamps
        count = 0
        window_start_time = timestamps[0]  # Start of the first time window
        time_window_count = 0  # Count of packets within the current time window
        
        for ts in timestamps:
            # Check if the current timestamp is within the time window from the start
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                # Move to the next time window
                window_start_time = ts
                time_window_count = 1  # Reset the count for the new window
            count = max(count, time_window_count)  # Track the maximum count within a window
        # Save the time window count for ct_dst_ltm
        print(f"ct_dst_ltm for {dst_ip}: {count}")
        packet_data['ct_dst_ltm'] += count

    # Calculate ct_src_dport_ltm for source IP and destination port over time
    for (src_ip, dst_port), timestamps in src_dport_ltm_counter.items():
        timestamps.sort()  # Sort the timestamps
        count = 0
        window_start_time = timestamps[0]  # Start of the first time window
        time_window_count = 0  # Count of packets within the current time window
        
        for ts in timestamps:
            # Check if the current timestamp is within the time window from the start
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                # Move to the next time window
                window_start_time = ts
                time_window_count = 1  # Reset the count for the new window
            count = max(count, time_window_count)  # Track the maximum count within a window
        # Save the time window count for ct_src_dport_ltm
        print(f"ct_src_dport_ltm for ({src_ip}, {dst_port}): {count}")
        packet_data['ct_src_dport_ltm'] += count

    # Calculate ct_dst_sport_ltm for destination IP and source port over time
    for (dst_ip, src_port), timestamps in dst_sport_ltm_counter.items():
        timestamps.sort()  # Sort the timestamps
        count = 0
        window_start_time = timestamps[0]  # Start of the first time window
        time_window_count = 0  # Count of packets within the current time window
        
        for ts in timestamps:
            # Check if the current timestamp is within the time window from the start
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                # Move to the next time window
                window_start_time = ts
                time_window_count = 1  # Reset the count for the new window
            count = max(count, time_window_count)  # Track the maximum count within a window
        # Save the time window count for ct_dst_sport_ltm
        print(f"ct_dst_sport_ltm for ({dst_ip}, {src_port}): {count}")
        packet_data['ct_dst_sport_ltm'] += count

    # Calculate ct_dst_src_ltm for source and destination IPs over time
    for (src_ip, dst_ip), timestamps in dst_src_ltm_counter.items():
        timestamps.sort()  # Sort the timestamps
        count = 0
        window_start_time = timestamps[0]  # Start of the first time window
        time_window_count = 0  # Count of packets within the current time window
        
        for ts in timestamps:
            # Check if the current timestamp is within the time window from the start
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                # Move to the next time window
                window_start_time = ts
                time_window_count = 1  # Reset the count for the new window
            count = max(count, time_window_count)  # Track the maximum count within a window
        # Save the time window count for ct_dst_src_ltm
        print(f"ct_dst_src_ltm for ({src_ip}, {dst_ip}): {count}")
        packet_data['ct_dst_src_ltm'] += count

    return packet_data

def calculate_intervals_and_jitter():
    for session_id, session in session_data.items():
        # Calculate sinpkt
        if len(session["timestamps_src"]) > 1:
            src_intervals = [
                session["timestamps_src"][i] - session["timestamps_src"][i - 1]
                for i in range(1, len(session["timestamps_src"]))
            ]
            session["sinpkt"] = sum(src_intervals) / len(src_intervals) if src_intervals else 0
            session["sjit"] = sum(abs(src_intervals[i] - src_intervals[i - 1]) for i in range(1, len(src_intervals))) / len(src_intervals) if len(src_intervals) > 1 else 0
        else:
            session["sinpkt"], session["sjit"] = 0, 0

        # Calculate dinpkt
        if len(session["timestamps_dst"]) > 1:
            dst_intervals = [
                session["timestamps_dst"][i] - session["timestamps_dst"][i - 1]
                for i in range(1, len(session["timestamps_dst"]))
            ]
            session["dinpkt"] = sum(dst_intervals) / len(dst_intervals) if dst_intervals else 0
            session["djit"] = sum(abs(dst_intervals[i] - dst_intervals[i - 1]) for i in range(1, len(dst_intervals))) / len(dst_intervals) if len(dst_intervals) > 1 else 0
        else:
            session["dinpkt"], session["djit"] = 0, 0



#  sloss and dloss: Simple initialization added for tracking purposes; logic to calculate these accurately in real-time would involve more advanced state tracking, possibly based on protocol acknowledgments

def process_packet(packet):
    global packet_count
    packet_count += 1  # Increment the packet count to assign unique Packet ID

    packet_info = {
        "packet_id": packet_count,
        "timestamp": time(),  
        "state": determine_state(packet) if TCP in packet else "UNKNOWN",
        "ttl": packet[IP].ttl if IP in packet else 0,
        "packet_size": len(packet) if IP in packet else 0
    }

    # Extract IP ID if IP layer is present
    if IP in packet:
        packet_info["ip_id"] = packet[IP].id
        packet_info["proto"] = packet[IP].proto
        packet_info["packet_size"] = len(packet)
        packet_info["ttl"] = packet[IP].ttl
    else:
        packet_info["ip_id"] = None
        packet_info["proto"] = None
        packet_info["packet_size"] = 0
        packet_info["ttl"] = 0

    if TCP in packet:
        packet_info["state"] = determine_state(packet)
    else:
        packet_info["state"] = "UNKNOWN"

    # Generate a Session ID if TCP or UDP layer is present
    if IP in packet and (TCP in packet or UDP in packet):
        protocol = "TCP" if TCP in packet else "UDP"
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport if TCP in packet or UDP in packet else None
        dst_port = packet.dport if TCP in packet or UDP in packet else None
        session_id = (src_ip, dst_ip, src_port, dst_port, protocol)
        packet_info["service"] = port_to_service.get(dst_port, "Unknown")

        # Update or create session record
        if session_id in session_data:
            # Update last seen timestamp for the session
            session_data[session_id]["last_timestamp"] = packet_info["timestamp"]

            # Count state_ttl for ct_state_ttl (same state and ttl)
            state_ttl_counter[(packet_info["state"], packet_info["ttl"])] += 1

            # Count packets for ct_dst_ltm (packets sent to destination over time)
            dst_ltm_counter[dst_ip].append(packet_info["timestamp"])

            # Count packets for ct_src_dport_ltm (packets from source to destination port over time)
            src_dport_ltm_counter[(src_ip, dst_port)].append(packet_info["timestamp"])

            # Count packets for ct_dst_sport_ltm (packets to destination IP from source port over time)
            dst_sport_ltm_counter[(dst_ip, src_port)].append(packet_info["timestamp"])

            # Count packets for ct_dst_src_ltm (packets exchanged between source and destination IPs over time)
            dst_src_ltm_counter[(src_ip, dst_ip)].append(packet_info["timestamp"])


            if packet[IP].src == src_ip:
                session_data[session_id]["spkts"] += 1  # Packet sent from source to destination
                session_data[session_id]["sbytes"] += packet_info["packet_size"]
                session_data[session_id]["sttl"] = packet_info["ttl"]
                session_data[session_id]["timestamps_src"].append(packet_info["timestamp"])
                session_data[session_id]["swin"] = packet[TCP].window
                session_data[session_id]["stcpb"] += len(packet[TCP].payload)

                session_data[session_id]["smean"] = session_data[session_id]["sbytes"] / session_data[session_id]["spkts"]
            else:
                session_data[session_id]["dpkts"] += 1
                session_data[session_id]["dbytes"] += packet_info["packet_size"]
                session_data[session_id]["dttl"] = packet_info["ttl"]
                session_data[session_id]["timestamps_dst"].append(packet_info["timestamp"])
                session_data[session_id]["dwin"] = packet[TCP].window
                session_data[session_id]["dtcpb"] += len(packet[TCP].payload)

                session_data[session_id]["dmean"] = session_data[session_id]["dbytes"] / session_data[session_id]["dpkts"]

                if "syn_timestamp" in session_data[session_id] and "synack_timestamp" in session_data[session_id]:
                    session_data[session_id]["tcprtt"] = session_data[session_id]["synack_timestamp"] - session_data[session_id]["syn_timestamp"]

                if "syn_timestamp" in session_data[session_id] and "synack_timestamp" not in session_data[session_id]:
                    if TCP in packet and packet[TCP].flags == "SA":  
                        session_data[session_id]["synack_timestamp"] = packet_info["timestamp"]
                        session_data[session_id]["synack"] = session_data[session_id]["synack_timestamp"] - session_data[session_id]["syn_timestamp"]

                if "data_timestamp" in session_data[session_id] and "ack_timestamp" not in session_data[session_id]:
                    if TCP in packet and packet[TCP].flags == "A": 
                        session_data[session_id]["ack_timestamp"] = packet_info["timestamp"]
                        session_data[session_id]["ackdat"] = session_data[session_id]["ack_timestamp"] - session_data[session_id]["data_timestamp"]

                if HTTP in packet:
                    if packet[HTTP].Method == "GET" or packet[HTTP].Method == "POST":
                        session_data[session_id]["trans_depth"] += 1
                if HTTPResponse in packet:
                    if "Content-Length" in packet[HTTPResponse].headers:
                        content_len = int(packet[HTTPResponse].headers["Content-Length"])
                        session_data[session_id]["response_body_len"] = content_len
                    elif TCP in packet and packet[TCP].payload:
                        session_data[session_id]["response_body_len"] = len(packet[TCP].payload)

                session_data[session_id]["ct_srv_src"] += 1
        else:
            session_data[session_id] = {
                "spkts": 0,
                "dpkts": 0,
                "sbytes": 0,
                "dbytes": 0,
                "sttl": packet_info["ttl"],
                "dttl": 0,
                "sload": 0,
                "dload": 0,
                "sloss": 0,
                "dloss": 0,
                "timestamps_src": [],  
                "timestamps_dst": [],  
                "sinpkt": 0,
                "dinpkt": 0,
                "sjit": 0,
                "djit": 0,
                "dttl": 0,
                "swin": 0,                
                "dwin": 0,        
                "stcpb": 0,       
                "dtcpb": 0,
                "first_timestamp": packet_info["timestamp"], 
                "last_timestamp": packet_info["timestamp"],
                "syn_timestamp": None,
                "synack_timestamp": None,
                "ack_timestamp": None,
                "data_timestamp": None,
                "tcprtt": None,
                "synack": None,
                "ackdat": None,
                "smean": 0,
                "dmean": 0,
                "trans_depth": 0,
                "response_body_len": 0,
                "ct_srv_src": 0,
                "ct_state_ttl": 0,
                "ct_dst_ltm": 0,
                "ct_src_dport_ltm": 0,
                "ct_dst_sport_ltm": 0,
                "ct_dst_src_ltm": 0
            }
        session_data[session_id]["duration"] = session_data[session_id]["last_timestamp"] - session_data[session_id]["first_timestamp"]
        packet_info["session_id"] = session_id
    else:
        packet_info["session_id"] = None
        packet_info["service"] = "Unknown"

    
    calculate_time_metrics([packet_info])

        # **Calculate FTP Metrics** if applicable
    if dst_port == 21 or src_port == 21:  # Check if it's an FTP connection
        calculate_ftp_metrics([packet_info])

        # **Calculate HTTP Metrics** if applicable
    if dst_port == 80 or src_port == 80 or packet_info["service"] == "HTTP":
        calculate_http_metrics([packet_info])

    return packet_info


def capture_packets(interface, packet_limit):
    try:
        captured_data = []
        
        print("Starting packet capture...")
        sniff(iface=interface, prn=lambda x: captured_data.append(process_packet(x)), stop_filter=lambda x: len(captured_data) >= packet_limit)

        if captured_data:
            print("Calculating metrics...")
            
            # Time-based metrics
            captured_data = calculate_time_metrics(captured_data)

            # FTP metrics
            captured_data = calculate_ftp_metrics(captured_data)

            # HTTP metrics
            captured_data = calculate_http_metrics(captured_data)

        print("Packet capture and metrics calculation completed.")
        return captured_data, session_data

    except Exception as e:
        print(f"Error during packet capture: {e}")
        # Return empty data to avoid unpacking issues
        return [], {}


# Usage example
interface = "Ethernet 3"  # Replace with your active network interface
packet_limit = 10   # Limit the number of packets to capture (for demo purposes)
captured_values, session_info = capture_packets(interface, packet_limit)

# Print captured packets and session information including sbytes, dbytes, duration, and rate
print("\nCaptured Packets:")
for captured in captured_values:
    print(captured)

print("\nSession Information:")
for session_id, info in session_info.items():
    print(f"Session ID: {session_id}, spkts: {info['spkts']}, dpkts: {info['dpkts']}, "
          f"sbytes: {info['sbytes']}, dbytes: {info['dbytes']}, "
          f"Duration: {info['duration']} seconds, Rate: {info['rate']} bytes/sec")

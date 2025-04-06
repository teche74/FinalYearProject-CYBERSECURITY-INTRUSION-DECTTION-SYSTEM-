from scapy.all import sniff, IP, TCP, UDP , conf
from time import time
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.http import HTTP, HTTPResponse
import csv
conf.verbose = False
import logging
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
ftp_login_counter = defaultdict(
    bool
)  # Track whether FTP login has occurred (True/False)
ftp_cmd_counter = defaultdict(int)  # Track count of FTP commands
http_method_counter = defaultdict(int)  # Track count of HTTP method

# Initialize counters and trackers
src_ltm_counter = defaultdict(
    int
)  # Count packets from source IPs within the last minute
srv_dst_counter = defaultdict(
    set
)  # Track distinct destination ports for each source IP
ips_ports_counter = defaultdict(set)  # Track source IPs and source ports
attack_category = defaultdict(
    str
)  # Placeholder for attack category (e.g., 'DoS', 'Probe')

label = defaultdict(str)  # Label the traffic as 'Normal' or 'Attack'

# Define FTP commands and HTTP methods of interest
ftp_commands = {"USER", "PASS", "QUIT", "RETR", "STOR", "DELE", "LIST"}
http_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}

port_to_service = {
    21: "FTP",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
}


def calculate_time_metrics(packet_data):
    """
    Calculate metrics: ct_src_ltm, ct_srv_dst, is_sm_ips_ports, attack_cat, and label based on packet data.
    """
    
    time_window = timedelta(minutes=1)  # Define a 1-minute time window

    for packet in packet_data:
        timestamp = packet['timestamp']
        print("Original timestamp:", timestamp)

        # Ensure timestamp is a Unix float and convert it to datetime
        if isinstance(timestamp, float):
            timestamp_dt = datetime.fromtimestamp(timestamp)
            print("Converted timestamp:", timestamp_dt)
        else:
            raise ValueError("Timestamp must be a Unix float.")

        # ct_src_ltm: Count how many packets from the source IP within the last minute
        current_time = timestamp_dt
        for other_packet in packet_data:
            other_timestamp = other_packet['timestamp']
            if isinstance(other_timestamp, float):
                other_timestamp_dt = datetime.fromtimestamp(other_timestamp)
            else:
                continue

            # Check if the other packet is within the time window
            if current_time - other_timestamp_dt <= time_window:
                src_ltm_counter[packet['src_ip']] += 1

        # ct_srv_dst: Count distinct destination ports (services) for the same source IP
        srv_dst_counter[packet['src_ip']].add(packet['dst_port'])

        # is_sm_ips_ports: Track source IPs and ports, flagging anomalies
        ips_ports_counter[(packet['src_ip'], packet['src_port'])].add(packet['dst_ip'])

        # Attack classification
        if packet['protocol'] == 'TCP' and packet['dst_port'] == 443:  # Example condition
            attack_category[packet['src_ip']] = 'DoS'  # Hypothetical attack category
            label[packet['src_ip']] = 'Attack'
        else:
            attack_category[packet['src_ip']] = 'Normal'
            label[packet['src_ip']] = 'Normal'

    # Calculate is_sm_ips_ports for all IP-port pairs
    is_small_ips_ports = {}
    for key, ip_ports in ips_ports_counter.items():
        is_small_ips_ports[key] = len(ip_ports) < 10 

    # Add calculated metrics to packets
    for packet in packet_data:
        ip = packet['src_ip']
        packet['ct_src_ltm'] = src_ltm_counter[ip]
        packet['ct_srv_dst'] = len(srv_dst_counter[ip])
        packet['is_sm_ips_ports'] = 'Yes' if is_small_ips_ports.get((ip, packet['src_port']), False) else 'No'
        packet['attack_cat'] = attack_category[ip]
        packet['label'] = label[ip]

    return packet_data


def calculate_packet_metrics(packet_info):
    # Calculate specific metrics for each packet
    src_ip =   packet_info["src_ip"]
    dst_ip =   packet_info["dst_ip"]
    src_port = packet_info["src_port"]
    dst_port = packet_info["dst_port"]

    # Count packets from src_ip within the last minute (ct_src_ltm)
    if src_ip:
        src_ltm_counter[src_ip] += 1
        packet_info["ct_src_ltm"] = src_ltm_counter[src_ip]

    # Count distinct destination ports from src_ip (ct_srv_dst)
    if src_ip and dst_port:
        srv_dst_counter[src_ip].add(dst_port)
        packet_info["ct_srv_dst"] = len(srv_dst_counter[src_ip])

    # Determine if small number of unique IPs and ports (is_sm_ips_ports)
    ips_ports_counter[(src_ip, src_port)].add((dst_ip, dst_port))
    is_sm_ips_ports = len(ips_ports_counter[(src_ip, src_port)]) < 5
    packet_info["is_sm_ips_ports"] = "Yes" if is_sm_ips_ports else "No"

    # Simple attack categorization
    if dst_port == 443:
        attack_category[src_ip] = "DoS"
        label[src_ip] = "Attack"
    else:
        attack_category[src_ip] = "Normal"
        label[src_ip] = "Normal"
    packet_info["attack_cat"] = attack_category[src_ip]
    packet_info["label"] = label[src_ip]

    if packet["protocol"] == 'FTP':
        ftp_cmd = packet['ftp_cmd']  # Get the FTP command from the packet data
        if ftp_cmd in ftp_commands:
            ftp_cmd_counter[ftp_cmd] += 1  # Count the FTP command
            # Check if login has occurred (USER/PASS sequence)
            if ftp_cmd == 'USER' or ftp_cmd == 'PASS':
                ftp_login_counter[packet['src_ip']] = True  # Mark FTP login as True

    elif packet["protocol"] == 'HTTP':
        http_method = packet['http_method']  # Get the HTTP method from the packet data
        if http_method in http_methods:
            http_method_counter[http_method] += 1  # Count the HTTP method
        packet["ct_flw_http_mthd"] = sum(http_method_counter.values())
    return packet_info


def calculate_ftp_metrics(packet_data, src_ip):
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
        # print(f"FTP login status for {ip}: {'Login Successful' if logged_in else 'Login Not Attempted'}")
        packet_data['ip']['is_ftp_login'] = 1 if logged_in else 0

    packet_data[-1].update(
        {
            "is_ftp_login": 1 if ftp_login_counter[src_ip] else 0,
            "ct_ftp_cmd": sum(ftp_cmd_counter.values()),
        }
    )
    return packet_data


def determine_state(packet):
    if TCP in packet:
        flags = packet[TCP].flags
        if flags & 0x01:  # FIN flag
            return "FIN"
        elif flags & 0x04:  # RST flag
            return "RST"
        elif flags & 0x02:  # SYN flag
            return "SYN"
        elif flags & 0x10:  # ACK flag
            return "ACK"
        elif tcp_flags & 0x04:  # RST flag is set
            return "INT"
        elif tcp_flags & 0x02 or tcp_flags & 0x10:  # SYN or ACK flags set
            return "CON"
    return "UNKNOWN"

def calculate_time_window_counts(packet_data):
    """
    Calculate and update time window-based metrics for packets in the provided data.
    """
    # Initialize counters
    for packet in packet_data:
        packet["ct_dst_ltm"] = 0
        packet["ct_src_dport_ltm"] = 0
        packet["ct_dst_sport_ltm"] = 0
        packet["ct_dst_src_ltm"] = 0

    # Calculate ct_dst_ltm for destination IP over time
    for dst_ip, timestamps in dst_ltm_counter.items():
        timestamps.sort()  # Sort the timestamps
        count = 0
        window_start_time = timestamps[0]  # Start of the first time window
        time_window_count = 0  # Count of packets within the current time window

        for ts in timestamps:
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                window_start_time = ts
                time_window_count = 1
            count = max(count, time_window_count)

        for packet in packet_data:
            if packet["dst_ip"] == dst_ip:
                packet["ct_dst_ltm"] += count

    # Calculate ct_src_dport_ltm for source IP and destination port over time
    for (src_ip, dst_port), timestamps in src_dport_ltm_counter.items():
        timestamps.sort()
        count = 0
        window_start_time = timestamps[0]
        time_window_count = 0

        for ts in timestamps:
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                window_start_time = ts
                time_window_count = 1
            count = max(count, time_window_count)

        for packet in packet_data:
            if packet["src_ip"] == src_ip and packet["dst_port"] == dst_port:
                packet["ct_src_dport_ltm"] += count

    # Calculate ct_dst_sport_ltm for destination IP and source port over time
    for (dst_ip, src_port), timestamps in dst_sport_ltm_counter.items():
        timestamps.sort()
        count = 0
        window_start_time = timestamps[0]
        time_window_count = 0

        for ts in timestamps:
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                window_start_time = ts
                time_window_count = 1
            count = max(count, time_window_count)

        for packet in packet_data:
            if packet["dst_ip"] == dst_ip and packet["src_port"] == src_port:
                packet["ct_dst_sport_ltm"] += count

    # Calculate ct_dst_src_ltm for source and destination IPs over time
    for (src_ip, dst_ip), timestamps in dst_src_ltm_counter.items():
        timestamps.sort()
        count = 0
        window_start_time = timestamps[0]
        time_window_count = 0

        for ts in timestamps:
            if ts - window_start_time <= TIME_WINDOW:
                time_window_count += 1
            else:
                window_start_time = ts
                time_window_count = 1
            count = max(count, time_window_count)

        for packet in packet_data:
            if packet["src_ip"] == src_ip and packet["dst_ip"] == dst_ip:
                packet["ct_dst_src_ltm"] += count

    return packet_data


def calculate_session_metrics(packet_data):
    """
    Update session-specific metrics for intervals and jitter.
    """
    for session_id, session in session_data.items():
        if len(session["timestamps_src"]) > 1:
            src_intervals = [
                session["timestamps_src"][i] - session["timestamps_src"][i - 1]
                for i in range(1, len(session["timestamps_src"]))
            ]
            session["sinpkt"] = (
                sum(src_intervals) / len(src_intervals) if src_intervals else 0
            )
            session["sjit"] = (
                sum(
                    abs(src_intervals[i] - src_intervals[i - 1])
                    for i in range(1, len(src_intervals))
                )
                / len(src_intervals)
                if len(src_intervals) > 1
                else 0
            )
        else:
            session["sinpkt"], session["sjit"] = 0, 0

        if len(session["timestamps_dst"]) > 1:
            dst_intervals = [
                session["timestamps_dst"][i] - session["timestamps_dst"][i - 1]
                for i in range(1, len(session["timestamps_dst"]))
            ]
            session["dinpkt"] = (
                sum(dst_intervals) / len(dst_intervals) if dst_intervals else 0
            )
            session["djit"] = (
                sum(
                    abs(dst_intervals[i] - dst_intervals[i - 1])
                    for i in range(1, len(dst_intervals))
                )
                / len(dst_intervals)
                if len(dst_intervals) > 1
                else 0
            )
        else:
            session["dinpkt"], session["djit"] = 0, 0


def update_session_data(session_id, packet_info):
    """
    Update session data with each packet's information, calculating duration and rate on the fly.

    packet_info is a dictionary containing:
    - 'timestamp': the timestamp of the packet
    - 'sbytes': source bytes in this packet
    - 'dbytes': destination bytes in this packet
    """
    # Initialize session data if it doesn't exist for this session_id
    if session_id not in session_data:
        session_data[session_id] = {
            "first_timestamp": packet_info["timestamp"],
            "last_timestamp": packet_info["timestamp"],
            "sbytes": 0,
            "dbytes": 0,
            "duration": 0,
            "rate": 0,
        }

    # Update session bytes
    session_data[session_id]["sbytes"] += packet_info["sbytes"]
    session_data[session_id]["dbytes"] += packet_info["dbytes"]

    # Update last timestamp and duration
    session_data[session_id]["last_timestamp"] = packet_info["timestamp"]
    session_data[session_id]["duration"] = (
        session_data[session_id]["last_timestamp"]
        - session_data[session_id]["first_timestamp"]
    )

    # Calculate rate (bytes per second) for this packet
    if session_data[session_id]["duration"] > 0:
        session_data[session_id]["rate"] = (
            session_data[session_id]["sbytes"] + session_data[session_id]["dbytes"]
        ) / session_data[session_id]["duration"]
    else:
        session_data[session_id]["rate"] = 0


def get_data_to_csv(packet_data , session_data , session_id):
    data = {
        "id" : packet_data["packet_id"],
        "dur" : session_data[session_id]["duration"],
        "proto" : packet_data["proto"],
        "service": packet_data["service"],
        "state": packet_data["state"],
        "spkts": session_data[session_id]["spkts"],
        "dpkts" : session_data[session_id]["dpkts"],
        "sbytes": session_data[session_id]["sbytes"],
        "dbytes" : session_data[session_id]["dbytes"],
        "rate" : session_data[session_id]["rate"],
        "sttl" : session_data[session_id]["sttl"] ,
        "dttl": session_data[session_id]["dttl"],
        "sload" : 0,
        "dload" : 0,
        "sloss" : 0,
        "dloss" : 0,
        "sinpkt" : session["sinpkt"],
        "dinpkt" : session["dinpkt"],
        "sjit" :  session["sjit"],
        "djit" : session["djit"] ,
        "swin" : session_data[session_id]["swin"] ,
        "stcpb" : session_data[session_id]["stcpb"],
        "dtcpb" : session_data[session_id]["dtcpb"],
        "dwin" : session_data[session_id]["dwin"],
        "tcprtt" : session_data[session_id]["tcprtt"],
        "synack" : session_data[session_id]["synack"] ,
        "ackdat" : session_data[session_id]["ackdat"],
        "smean" : session_data[session_id]["smean"],
        "dmean" : session_data[session_id]["dmean"],
        "trans_depth" : session_data[session_id]["trans_depth"] ,
        "response_body_len" : session_data[session_id]["response_body_len"],
        "ct_srv_src" : session_data[session_id]["ct_srv_src"],
        "ct_state_ttl" : state_ttl_counter[(packet_data["state"], packet_data["ttl"])],
        "ct_dst_ltm" : packet_data["ct_dst_ltm"]  ,
        "ct_src_dport_ltm" : packet_data["ct_src_dport_ltm"],
        "ct_dst_sport_ltm" : packet_data["ct_dst_sport_ltm"],
        "ct_dst_src_ltm" : packet_data["ct_dst_src_ltm"],
        "is_ftp_login"  : packet_data["is_ftp_login"],
        "ct_ftp_cmd" : packet_data["ct_ftp_cmd"],
        "ct_flw_http_mthd" : packet_data["ct_flw_http_mthd"],
        "ct_src_ltm" : packet_data["ct_src_ltm"],
        "ct_srv_dst" : packet_data["ct_srv_dst"],
        "is_sm_ips_ports" : packet_data["is_sm_ips_ports"],
        "attack_cat" : packet_data["attack_cat"],
        "label" : packet_data["label"],
    }

    with open("session_data.csv", mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
    
    for packet in packets:
        row = process_packet(packet)
        writer.writerow(row)


#  sloss and dloss: Simple initialization added for tracking purposes; logic to calculate these accurately in real-time would involve more advanced state tracking, possibly based on protocol acknowledgments


def process_packet(packet):
    global packet_count
    packet_count += 1  # Increment the packet count to assign unique Packet ID

    packet_info = {
        "packet_id": packet_count,
        "timestamp": time(),
        "state": determine_state(packet) if TCP in packet else "UNKNOWN",
        "ttl": packet[IP].ttl if IP in packet else 0,
        "packet_size": len(packet) if IP in packet else 0,
    }

    # Extract IP ID if IP layer is present
    if IP in packet:
        packet_info["ip_id"] = packet[IP].id
        packet_info["proto"] = packet[IP].proto
        packet_info["ttl"] = packet[IP].ttl
    else:
        packet_info["ip_id"] = None
        packet_info["proto"] = None
        packet_info["ttl"] = 0

    if TCP in packet:
        packet_info["state"] = determine_state(packet)
    else:
        packet_info["state"] = "UNKNOWN"

    # Generate a Session ID if TCP or UDP layer is present
    if IP in packet and (TCP in packet or UDP in packet):
        protocol = "TCP" if TCP in packet else "UDP"
        packet_info["protocol"] = protocol
        src_ip = packet[IP].src
        packet_info["src_ip"] = src_ip 
        dst_ip = packet[IP].dst
        packet_info["dst_ip"] = dst_ip 

        src_port = packet.sport if TCP in packet or UDP in packet else None
        packet_info["src_port"] = src_port 

        dst_port = packet.dport if TCP in packet or UDP in packet else None
        packet_info["dst_port"] = dst_port 

        session_id = (src_ip, dst_ip, src_port, dst_port, protocol)
            
        
        packet_info["session_id"] = {
            "src_ip" : src_ip, 
            "dst_ip" :dst_ip, 
            "src_port" :src_port, 
            "dst_port" :dst_port, 
            "protocol" : protocol
            }

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
                session_data[session_id]["spkts"] += 1 
                session_data[session_id]["sbytes"] += packet_info["packet_size"]
                session_data[session_id]["sttl"] = packet_info["ttl"]
                session_data[session_id]["timestamps_src"].append(packet_info["timestamp"])
                session_data[session_id]["swin"] = packet[TCP].window
                session_data[session_id]["stcpb"] += len(packet[TCP].payload)

                session_data[session_id]["smean"] = (
                    session_data[session_id]["sbytes"]
                    / session_data[session_id]["spkts"]
                )
            else:
                session_data[session_id]["dpkts"] += 1
                session_data[session_id]["dbytes"] += packet_info["packet_size"]
                session_data[session_id]["dttl"] = packet_info["ttl"]
                session_data[session_id]["timestamps_dst"].append(
                    packet_info["timestamp"]
                )
                session_data[session_id]["dwin"] = packet[TCP].window
                session_data[session_id]["dtcpb"] += len(packet[TCP].payload)

                session_data[session_id]["dmean"] = (
                    session_data[session_id]["dbytes"]
                    / session_data[session_id]["dpkts"]
                )

                if (
                    "syn_timestamp" in session_data[session_id]
                    and "synack_timestamp" in session_data[session_id]
                ):
                    session_data[session_id]["tcprtt"] = (
                        session_data[session_id]["synack_timestamp"]
                        - session_data[session_id]["syn_timestamp"]
                    )

                if (
                    "syn_timestamp" in session_data[session_id]
                    and "synack_timestamp" not in session_data[session_id]
                ):
                    if TCP in packet and packet[TCP].flags == "SA":
                        session_data[session_id]["synack_timestamp"] = packet_info[
                            "timestamp"
                        ]
                        session_data[session_id]["synack"] = (
                            session_data[session_id]["synack_timestamp"]
                            - session_data[session_id]["syn_timestamp"]
                        )

                if (
                    "data_timestamp" in session_data[session_id]
                    and "ack_timestamp" not in session_data[session_id]
                ):
                    if TCP in packet and packet[TCP].flags == "A":
                        session_data[session_id]["ack_timestamp"] = packet_info[
                            "timestamp"
                        ]
                        session_data[session_id]["ackdat"] = (
                            session_data[session_id]["ack_timestamp"]
                            - session_data[session_id]["data_timestamp"]
                        )

                if HTTP in packet:
                    if packet[HTTP].Method == "GET" or packet[HTTP].Method == "POST":
                        session_data[session_id]["trans_depth"] += 1
                if HTTPResponse in packet:
                    if "Content-Length" in packet[HTTPResponse].headers:
                        content_len = int(
                            packet[HTTPResponse].headers["Content-Length"]
                        )
                        session_data[session_id]["response_body_len"] = content_len
                    elif TCP in packet and packet[TCP].payload:
                        session_data[session_id]["response_body_len"] = len(
                            packet[TCP].payload
                        )

                session_data[session_id]["ct_srv_src"] += 1
            update_session_data(session_id, packet_info) 
            calculate_ftp_metrics
            packet_info["session_data"] = session_data
        else:
            # session_id = f"{packet_info.get('src_ip', 'unknown')}-{packet_info.get('dst_ip', 'unknown')}-{src_port}-{dst_port}"
            packet_info["session_id"] = {
            "src_ip" : 0, 
            "dst_ip" :0, 
            "src_port" :0, 
            "dst_port" :0, 
            "protocol" : 0
            }

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
                "syn_timestamp": 0,
                "synack_timestamp": 0,
                "ack_timestamp": 0,
                "data_timestamp": 0,
                "tcprtt": 0,
                "synack": 0,
                "ackdat": 0,
                "smean": 0,
                "dmean": 0,
                "trans_depth": 0,
                "response_body_len": 0,
                "ct_srv_src": 0,
                "ct_state_ttl": 0,
                "ct_dst_ltm": 0,
                "ct_src_dport_ltm": 0,
                "ct_dst_sport_ltm": 0,
                "ct_dst_src_ltm": 0,
            }
        packet_info["session_id"] = session_id
    else:
        packet_info["service"] = "Unknown"

    
    packet_info["session_data"] = session_data
    return packet_info


def process_packet_and_calculate_features(packet_data):
    processed_data = process_packet(packet_data)
    print("processed data : " , processed_data)
    # processed_data_with_time_features  = calculate_time_metrics(processed_data)
    # print("time features : " , processed_data_with_time_features)
    process_data_with_metrics = calculate_packet_metrics(processed_data)
    print("metrics : ", process_data_with_metrics)
    calculate_session_metrics(process_data_with_metrics)
    return process_data_with_metrics

def capture_packets(interface="Ethernet 3"):
    captured_data = []

    print("Starting packet capture...")
    sniff(
        iface=interface, prn=lambda x: captured_data.append(process_packet_and_calculate_features(x)), count=5, filter = "ip"
    )

    return captured_data, session_data


interface = "Ethernet 3"
captured_values, session_info = capture_packets(interface)

# Print captured packets and session information including sbytes, dbytes, duration, and rate
print("\nCaptured Packets:")
for captured in captured_values:
    print(captured ,"\n")

# print(session_info.items())

# print("\nSession Information:")
# for session_id, info in session_info.items():
#     print(
#         f"Session ID: {session_id}, spkts: {info['spkts']}, dpkts: {info['dpkts']}, "
#         f"sbytes: {info['sbytes']}, dbytes: {info['dbytes']}, "
#         f"Duration: {info['duration']} seconds, Rate: {info['rate']} bytes/sec"
#     )

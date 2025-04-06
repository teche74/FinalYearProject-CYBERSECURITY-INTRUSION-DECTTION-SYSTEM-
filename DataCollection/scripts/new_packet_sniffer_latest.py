from scapy.all import sniff, IP, TCP, UDP
from time import time
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.http import HTTP, HTTPResponse
import csv
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


TIME_WINDOW = timedelta(minutes=1)

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.session_data = {}

        self.state_ttl_counter = defaultdict(int) 
        self.dst_ltm_counter = defaultdict(list)  
        self.src_dport_ltm_counter = defaultdict(list)  
        self.dst_sport_ltm_counter = defaultdict(list)  
        self.dst_src_ltm_counter = defaultdict(list)

        self.ftp_login_counter = defaultdict(bool)  
        self.ftp_cmd_counter = defaultdict(int)  
        self.http_method_counter = defaultdict(int)

        self.src_ltm_counter = defaultdict(int)    
        self.srv_dst_counter = defaultdict(set)   
        self.ips_ports_counter = defaultdict(set) 
        self.attack_category = defaultdict(str)

        self.label = defaultdict(str)

        self.ftp_commands = {"USER", "PASS", "QUIT", "RETR", "STOR", "DELE", "LIST"}
        self.http_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}

        self.port_to_service = {
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

    def _convert_timestamp(self, timestamp):
        """Convert Unix timestamp to datetime."""
        if isinstance(timestamp, float):
            return datetime.fromtimestamp(timestamp)
        else:
            raise ValueError("Timestamp must be a Unix float.")

    def get_tcp_state(self, packet):
        """Returns the TCP state."""
        if packet[TCP].flags == "S":
            return "SYN_SENT"
        elif packet[TCP].flags == "SA":
            return "SYN_ACK"
        elif packet[TCP].flags == "A":
            return "ACK"
        return "UNKNOWN"

    def extract_session_info(self, packet, packet_info):
        """Extracts session information (IP, ports, protocol) from the packet."""
        if IP in packet and (TCP in packet or UDP in packet):
            protocol = "TCP" if TCP in packet else "UDP"
            packet_info["protocol"] = protocol
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet.sport if TCP in packet or UDP in packet else None
            dst_port = packet.dport if TCP in packet or UDP in packet else None

            packet_info["src_ip"] = src_ip
            packet_info["dst_ip"] = dst_ip
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port

            session_id = (src_ip, dst_ip, src_port, dst_port, protocol)
            packet_info["session_id"] = session_id
            packet_info["service"] = self.port_to_service.get(dst_port, "Unknown")

            self.update_session_data(packet, packet_info)

    
    def update_session_data(self, packet, packet_info):
        """Updates session data based on the extracted packet information."""
        session_id = packet_info["session_id"]
        if session_id not in self.session_data:
            self.initialize_session_data(session_id, packet_info)

        session = self.session_data[session_id]
        session["last_timestamp"] = packet_info["timestamp"]
        
        self.state_ttl_counter[(packet_info["state"], packet_info["ttl"])] += 1
        self.dst_ltm_counter[packet_info["dst_ip"]].append(packet_info["timestamp"])
        
        self.count_packets_by_direction(packet, session, packet_info)
        self.update_metrics(session, packet_info , packet)

    def initialize_session_data(self, session_id, packet_info):
        """Initializes the session data for a new session."""
        self.session_data[session_id] = {
            "spkts": 0, "dpkts": 0, "sbytes": 0, "dbytes": 0, "sttl": packet_info["ttl"],
            "dttl": 0, "timestamps_src": [], "timestamps_dst": [], "sinpkt": 0, "dinpkt": 0,
            "sjit": 0, "djit": 0, "swin": 0, "dwin": 0, "stcpb": 0, "dtcpb": 0, "first_timestamp": packet_info["timestamp"],
            "last_timestamp": packet_info["timestamp"], "tcprtt": 0, "synack": 0, "ackdat": 0,
            "smean": 0, "dmean": 0, "trans_depth": 0, "response_body_len": 0, "ct_srv_src": 0,
            "ct_state_ttl": 0, "ct_dst_ltm": 0, "ct_src_dport_ltm": 0, "ct_dst_sport_ltm": 0, "ct_dst_src_ltm": 0
        }

    def count_packets_by_direction(self, packet, session, packet_info):
        """Counts packets sent or received based on the packet direction."""
        if packet[IP].src == packet_info["src_ip"]:
            session["spkts"] += 1
            session["sbytes"] += packet_info["packet_size"]
            session["smean"] = session["sbytes"] / session["spkts"]
        else:
            session["dpkts"] += 1
            session["dbytes"] += packet_info["packet_size"]
            session["dmean"] = session["dbytes"] / session["dpkts"]

    def update_metrics(self, session, packet_info, packet):
        """Updates specific session metrics."""
        if "syn_timestamp" in session and "synack_timestamp" not in session:
            if packet[TCP].flags == "SA":
                session["synack_timestamp"] = packet_info["timestamp"]
                packet["synack_timestamp"] = session["synack_timestamp"] 
                session["synack"] = session["synack_timestamp"] - session["syn_timestamp"]
                packet["synack"] = session["synack"]

        if "data_timestamp" in session and "ack_timestamp" not in session:
            if packet[TCP].flags == "A":
                session["ack_timestamp"] = packet_info["timestamp"]
                packet["ack_timestamp"] = session["ack_timestamp"]
                session["ackdat"] = session["ack_timestamp"] - session["data_timestamp"]
                packet["ackdat"] = session["ackdat"]

        if HTTP in packet:
            if packet[HTTP].Method in ["GET", "POST"]:
                session["trans_depth"] += 1
                packet["trans_depth"] = session["trans_depth"]
        
        if HTTPResponse in packet:
            content_len = int(packet[HTTPResponse].headers.get("Content-Length", 0))
            session["response_body_len"] = content_len if content_len else len(packet[TCP].payload)
            packet["response_body_len"]= session["response_body_len"]


    def determine_state(self, packet):
        """Determines the state based on the TCP/UDP layer."""
        if TCP in packet:
            return self.get_tcp_state(packet)
        return "UNKNOWN"

    def update_http_method_counter(self, packet):
        """Count HTTP methods like GET, POST."""
        if HTTP in packet:
            method = packet[HTTP].Method
            if method in self.http_methods:
                self.http_method_counter[method] += 1
                logging.info(f"HTTP {method} packet captured")


    def process_packet(self, packet):
        self.packet_count += 1

        packet_info = {}

        if IP in packet and (TCP in packet or UDP in packet):  # Ensure IP and protocol layers are present
            packet_info["packet_id"] = self.packet_count
            packet_info["timestamp"] = time()
            packet_info["state"] = self.determine_state(packet)
            packet_info["ttl"] = packet[IP].ttl if IP in packet else 0
            packet_info["packet_size"] = len(packet) if IP in packet else 0
            packet_info["ip_id"] = packet[IP].id if IP in packet else None
            packet_info["proto"] = packet[IP].proto if IP in packet else None

            self.extract_session_info(packet, packet_info)
            self.update_session_data(packet, packet_info)
            self.update_http_method_counter(packet)
            

        return packet_info 

    def calculate_time_metrics(self, packets_data):
        """Calculate time-related metrics such as ct_src_ltm, ct_srv_dst, attack category, and label."""
        for packet in packets_data:
            timestamp = packet['timestamp']
            print("Original timestamp:", timestamp)

            timestamp_dt = self._convert_timestamp(timestamp)
            print("Converted timestamp:", timestamp_dt)

            current_time = timestamp_dt
            for other_packet in packets_data:
                other_timestamp = other_packet['timestamp']
                other_timestamp_dt = self._convert_timestamp(other_timestamp)

                if current_time - other_timestamp_dt <= TIME_WINDOW:
                    self.src_ltm_counter[packet['src_ip']] += 1
                
            self.srv_dst_counter[packet['src_ip']].add(packet['dst_port'])
            self.ips_ports_counter[(packet['src_ip'], packet['src_port'])].add(packet['dst_ip'])

            if packet['protocol'] == 'TCP' and packet['dst_port'] == 443: 
                self.attack_category[packet['src_ip']] = 'DoS'
                self.label[packet['src_ip']] = 'Attack'
            else:
                self.attack_category[packet['src_ip']] = 'Normal'
                self.label[packet['src_ip']] = 'Normal'

        is_small_ips_ports = {}
        for key, ip_ports in self.ips_ports_counter.items():
            is_small_ips_ports[key] = len(ip_ports) < 10

        for packet in packets_data:
            ip = packet['src_ip']
            packet['ct_src_ltm'] = self.src_ltm_counter[ip]
            packet['ct_srv_dst'] = len(self.srv_dst_counter[ip])
            packet['attack_category'] = self.attack_category[ip]
            packet['label'] = self.label[ip]
            packet['is_small_ips_ports'] = is_small_ips_ports.get((ip, packet['src_port']), False)
    
    def save_to_csv(self, packets_data, filename="packets_data.csv"):
        """Save packet data to CSV."""
        keys = packets_data[0].keys()
        with open(filename, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            writer.writerows(packets_data)

    def start_sniffing(self, filter=None):
        """Start sniffing packets."""
        sniff(filter="ip", prn= lambda x : self.process_packet(x), store= 0, count=10)


sniffer = PacketSniffer()
sniffer.start_sniffing()

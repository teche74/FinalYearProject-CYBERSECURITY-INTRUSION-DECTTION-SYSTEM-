from scapy.all import sniff, IP, TCP, UDP , raw , in4_chksum
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.http import HTTP, HTTPResponse
from time import time, sleep
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.http import HTTP, HTTPResponse
import csv
import logging
import psutil
import socket
import datetime
import json
from kafka import KafkaProducer
from kafka.errors import KafkaError
from dotenv import load_dotenv
import os
from fastavro.schema import load_schema
from fastavro import writer
import io
import geoip2.database
import requests
import math
import subprocess

logging.basicConfig(
    filename="C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/IDS logging info/sniffer.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

load_dotenv()
RATE_TIME_WINDOW = 1
TIME_WINDOW = timedelta(minutes=1)
city_reader = geoip2.database.Reader(os.getenv('GEOLITE_CITY_PATH'))

connections = {}
sessions = {}


class NetworkMetrics:
    def __init__(self):
        self.total_connections = 0
        self.total_connections_with_error = 0
        self.total_connections_rejected = 0
        self.total_connections_to_same_service = 0
        self.connections_to_same_service_with_error = 0
        self.connections_to_same_service_rejected = 0
        self.consecutive_connections_to_same_service = 0
        self.consecutive_connections_to_different_services = 0
        self.connections_to_same_service_from_diff_hosts = 0
        self.protocol_traffic_volume = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        
        self.last_service = None
        self.last_host = None
        self.hosts_per_service = {}  

    def process_packet(self,packet , current_time, network_metrics ):
        def calculate_entropy(payload):
            if not payload:
                return None
            byte_counts = {byte: payload.count(byte) for byte in set(payload)}
            entropy = -sum((count / len(payload)) * math.log2(count / len(payload)) for count in byte_counts.values())
            return entropy

        def verify_udp_checksum(ip_pkt, udp_pkt):
            udp_raw = raw(udp_pkt)
            ip_raw = raw(ip_pkt)
            checksum = in4_chksum(socket.IPPROTO_UDP, ip_pkt, udp_raw)
            return checksum == udp_pkt.chksum

        def identify_service(src_port, dst_port):
            """Identify the service based on the port number."""
            service_map = {
                80: "HTTP",
                443: "HTTPS",
                21: "FTP",
                22: "SSH",
                53: "DNS",
                25: "SMTP",
                110: "POP3",
                143: "IMAP",
            }

            return service_map.get(src_port, service_map.get(dst_port, "Unknown Service"))

        
        def find_protocol(packet):
            """
            Finds the protocol used in the given packet and returns the protocol name.
            """
            if IP in packet:
                ip_proto = packet[IP].proto
                if ip_proto == 1:
                    return "ICMP"
                elif ip_proto == 6:
                    return "TCP"
                elif ip_proto == 17:
                    return "UDP"
                elif ip_proto == 2:
                    return "IGMP"
                else:
                    return f"Other IP Protocol: {ip_proto}"

            elif ARP in packet:
                return "ARP"

            elif Ether in packet:
                eth_type = packet[Ether].type
                if eth_type == 0x0800:
                    return "IPv4"
                elif eth_type == 0x86dd:
                    return "IPv6"
                elif eth_type == 0x0806:
                    return "ARP"
                else:
                    return f"Ethernet Type: {hex(eth_type)}"

            elif Raw in packet:
                return "Raw Data"

            return "Unknown Protocol"

        def get_request_rate(ip, current_time):
            """Track requests per second for an IP."""
            session = sessions.get(ip, {"count": 0, "timestamp": current_time})
            time_diff = current_time - session["timestamp"]
            if time_diff < RATE_TIME_WINDOW:
                request_rate = session["count"] / time_diff
            else:
                request_rate = 0
            sessions[ip] = {"count": session["count"] + 1, "timestamp": current_time}
            return request_rate

            return session["request_count"] / RATE_TIME_WINDOW

        def track_session(session_key, current_time):
            if session_key not in sessions:
                sessions[session_key] = {"start_time": current_time, "end_time": None}
            
            session = sessions[session_key]
            session["end_time"] = current_time

            duration = session["end_time"] - session["start_time"]
            return {"start_time": session["start_time"], "end_time": session["end_time"], "duration": duration}


        def get_ip_reputation(ip):
            try:
                response = requests.get(f'https://api.abuseipdb.com/api/v2/check', 
                                        params={'ipAddress': ip}, 
                                        headers={'Key': '4a9acce5802e21fe30ba681332598dc85414a653dea1640431d950c7b4f535f67f38dd1ee0d08fc1'})
                data = response.json()
                return data.get("data", {}).get("abuseConfidenceScore", None)
            except Exception as e:
                print(f"Error fetching IP reputation for {ip}: {e}")
                return None


        def track_traffic_by_protocol(proto):
            if proto == 6:  # TCP
                self.protocol_traffic_volume["TCP"] += 1
            elif proto == 17:  # UDP
                self.protocol_traffic_volume["UDP"] += 1
            elif proto == 1:  # ICMP
                self.protocol_traffic_volume["ICMP"] += 1
            else:
                self.protocol_traffic_volume["Other"] += 1
            return self.protocol_traffic_volume


        def detect_ip_anomalies(src_ip, dst_ip):
            """Detect IP anomalies (e.g., multiple requests from same source)."""
            current_time = time()
            src_count = sessions.get(src_ip, {"count": 0, "timestamp": current_time})["count"]
            sessions[src_ip] = {"count": src_count + 1, "timestamp": current_time}
            return src_count > 100

        def check_retransmission(packet):
            """Check if this packet is a retransmission."""
            if hasattr(packet, 'TCP') and packet[TCP].flags == "R": 
                return True
            return False 

        def get_geolocation(ip_address):
            """Get geolocation information for a given IP address using multiple sources."""
            geolocation_data = {}

            try:
                response = city_reader.city(ip_address)
                geolocation_data = {
                    "city": response.city.name,
                    "region": response.subdivisions.most_specific.name,
                    "country": response.country.name,
                    "continent": response.continent.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude
                }
                return geolocation_data  
            except Exception as e:
                logging.warning(f"GeoIP2 lookup failed for {ip_address}: {e}")

            try:
                response = requests.get(f'https://ipinfo.io/{ip_address}/json')
                if response.status_code == 200:
                    data = response.json()
                    geolocation_data = {
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "country": data.get("country"),
                        "continent": None,  
                        "latitude": None,   
                        "longitude": None,  
                    }
                    
                    if "loc" in data:
                        lat, lon = data["loc"].split(",")
                        geolocation_data["latitude"] = float(lat)
                        geolocation_data["longitude"] = float(lon)
                    return geolocation_data  
            except Exception as e:
                logging.warning(f"ipinfo.io lookup failed for {ip_address}: {e}")
            
            try:
                response = requests.get(f'http://ip-api.com/json/{ip_address}')
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        geolocation_data = {
                            "city": data.get("city"),
                            "region": data.get("regionName"),
                            "country": data.get("country"),
                            "continent": None,
                            "latitude": data.get("lat"),
                            "longitude": data.get("lon"),
                        }
                        return geolocation_data
            except Exception as e:
                logging.warning(f"ip-api.com lookup failed for {ip_address}: {e}")

            return None


        packet_data = {}


        if TCP in packet:
            packet_data = {
                "protocol": "TCP",
                "timestamp": packet.time,
                "duration": None,
                "service": "unknown",
                "src_bytes": packet[IP].len, 
                "dst_bytes": packet[IP].len,
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "src_port": packet[TCP].sport,
                "dst_port": packet[TCP].dport,
                "flags": packet.sprintf("%TCP.flags%"),
                "tcp_window_size": packet[TCP].window,
                "fragmented": bool(packet[IP].flags & 0x1),
                "payload_size": len(packet[TCP].payload),
                "ttl": packet[IP].ttl,
                "wrong_fragment": packet[IP].frag,
                "urgent": packet[TCP].urgptr,
                "land": 1 if packet[IP].src == packet[IP].dst else 0,
                "payload_entropy": calculate_entropy(bytes(packet[TCP].payload)) if len(packet[TCP].payload) > 0 else None,
                "attack_cat" : "Normal"
            }

            service = identify_service(packet[TCP].sport, packet[TCP].dport)
            host = packet[IP].src
            network_metrics.process_connection(service, host, packet_size=len(packet[TCP].payload), protocol="TCP")
            packet_data['metrics'] = network_metrics.calculate_metrics()

            flags = packet.sprintf("%TCP.flags%")

            packet_data["src_ip_geolocation"] = get_geolocation(packet[IP].src)
            packet_data["dst_ip_geolocation"] = get_geolocation(packet[IP].dst)

            packet_data["src_ip_reputation"] = get_ip_reputation(packet[IP].src)
            packet_data["dst_ip_reputation"] = get_ip_reputation(packet[IP].dst)

            packet_data["malicious_ip"] = (packet_data["src_ip_reputation"] > 50 or packet_data["dst_ip_reputation"] > 50)

            packet_data["protocol_traffic_volume"] = track_traffic_by_protocol(packet[IP].proto)

            packet_data["ip_anomaly"] = detect_ip_anomalies(packet[IP].src, packet[IP].dst)

            packet_data["retransmission"] = check_retransmission(packet)

            packet_data["is_syn_scan"] = 'S' in flags and not ('A' in flags or 'P' in flags)

            connection_key = (packet[IP].src, packet[IP].dst, packet[IP].proto)
            if connection_key in connections:
                connection_start_time = connections[connection_key]
                packet_data["duration"] = current_time - connection_start_time
            else:
                connections[connection_key] = current_time

            packet_data["request_rate"] = get_request_rate(packet[IP].src, current_time)
            
            if packet.haslayer(TCP):
                session_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
            else:
                session_key = None

            if session_key:
                packet_data["session_info"] = track_session(session_key, current_time)
        
        elif UDP in packet:
            packet_data = {
                "protocol": "UDP",
                "timestamp": packet.time,
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "src_port": packet[UDP].sport,
                "fragmented": bool(packet[IP].flags & 0x1),
                "dst_port": packet[UDP].dport,
                "payload_size": len(packet[UDP].payload),
                "ttl": packet[IP].ttl,
                "flags": packet.sprintf("%TCP.flags%"),
                "payload_entropy": calculate_entropy(bytes(packet[UDP].payload)) if len(packet[UDP].payload) > 0 else None,
                "udp_checksum_valid": verify_udp_checksum(packet[IP], packet[UDP]),
                "attack_cat" : "Normal" 
            }

            service = identify_service(packet[UDP].sport, packet[UDP].dport)
            host = packet[IP].src
            network_metrics.process_connection(service, host, packet_size=len(packet[UDP].payload), protocol="UDP")
            packet_data['metrics'] = network_metrics.calculate_metrics()


            flags = packet.sprintf("%TCP.flags%")

            packet_data["src_ip_geolocation"] = get_geolocation(packet[IP].src)
            packet_data["dst_ip_geolocation"] = get_geolocation(packet[IP].dst)

            packet_data["src_ip_reputation"] = get_ip_reputation(packet[IP].src)
            packet_data["dst_ip_reputation"] = get_ip_reputation(packet[IP].dst)

            packet_data["malicious_ip"] = (packet_data["src_ip_reputation"] > 50 or packet_data["dst_ip_reputation"] > 50)

            packet_data["protocol_traffic_volume"] = track_traffic_by_protocol(packet[IP].proto)

            packet_data["ip_anomaly"] = detect_ip_anomalies(packet[IP].src, packet[IP].dst)

            packet_data["retransmission"] = check_retransmission(packet)
            

            connection_key = (packet[IP].src, packet[IP].dst, packet[IP].proto)
            if connection_key in connections:
                connection_start_time = connections[connection_key]
                packet_data["connection_duration"] = current_time - connection_start_time
            else:
                connections[connection_key] = current_time

            packet_data["request_rate"] = get_request_rate(packet[IP].src, current_time)

            if packet.haslayer(UDP):
                session_key = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport)
            else:
                session_key = None

            if session_key:
                packet_data["session_info"] = track_session(session_key, current_time)
        
        elif IP in packet and not (TCP in packet or UDP in packet): 
            packet_data = {
                "protocol": packet[IP].proto,
                "timestamp": packet.time,
                "packet_length": len(packet),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "ttl": packet[IP].ttl,
                "flags": packet.sprintf("%TCP.flags%"),
                "fragmented": bool(packet[IP].flags & 0x1),
                "payload_size": len(packet[IP].payload),
                "payload_entropy": calculate_entropy(bytes(packet[IP].payload)) if len(packet[IP].payload) > 0 else None,
                "attack_cat" : "Normal"
            }

            service = identify_service(packet[IP].sport, packet[IP].dport)
            host = packet[IP].src

            packet_protocol = find_protocol(packet) 
            
            network_metrics.process_connection(service, host, packet_size=len(packet[packet_protocol].payload), protocol=packet_protocol)
            packet_data['metrics'] = network_metrics.calculate_metrics()

            flags = packet.sprintf("%TCP.flags%")

            packet_data["src_ip_geolocation"] = get_geolocation(packet[IP].src)
            packet_data["dst_ip_geolocation"] = get_geolocation(packet[IP].dst)

            packet_data["src_ip_reputation"] = get_ip_reputation(packet[IP].src)
            packet_data["dst_ip_reputation"] = get_ip_reputation(packet[IP].dst)

            packet_data["malicious_ip"] = (packet_data["src_ip_reputation"] > 50 or packet_data["dst_ip_reputation"] > 50)

            packet_data["protocol_traffic_volume"] = track_traffic_by_protocol(packet[IP].proto)

            packet_data["ip_anomaly"] = detect_ip_anomalies(packet[IP].src, packet[IP].dst)

            packet_data["retransmission"] = check_retransmission(packet)

            connection_key = (packet[IP].src, packet[IP].dst, packet[IP].proto)
            if connection_key in connections:
                connection_start_time = connections[connection_key]
                packet_data["connection_duration"] = current_time - connection_start_time
            else:
                connections[connection_key] = current_time

            packet_data["request_rate"] = get_request_rate(packet[IP].src, current_time)

            if packet.haslayer("DNS"):
                dns = packet["DNS"]
                packet_data.update({
                    "dns_query": dns.qd.qname.decode("utf-8") if dns.qdcount > 0 else None,
                    "dns_response_code": dns.rcode,
                    "dns_query_type": dns.qd.qtype if dns.qdcount > 0 else None,
                    "dns_response_count": len(dns.an)
                })
            elif packet.haslayer(Raw): 
                raw_data = packet[Raw].load.decode(errors="ignore")
                if "HTTP" in raw_data:
                    http_method = None
                    http_host = None
                    http_path = None
                    
                    lines = raw_data.split("\r\n")
                    if lines:
                        first_line = lines[0].split(" ")
                        if len(first_line) >= 3:
                            http_method = first_line[0]
                            http_host = lines[1].split(":")[1].strip() if len(lines) > 1 and "Host:" in lines[1] else None
                            http_path = first_line[1]
                            
                    packet_data.update({
                        "http_method": http_method,
                        "http_host": http_host,
                        "http_path": http_path
                    })
        return packet_data

    def process_connection(self, service, host, is_error=False, is_rejected=False, packet_size=0, protocol=None):
        
        self.total_connections += 1

        if protocol:
            if protocol in self.protocol_traffic_volume:
                self.protocol_traffic_volume[protocol] += packet_size
            else:
                self.protocol_traffic_volume["Other"] += packet_size
        
        if service == self.last_service:
            self.total_connections_to_same_service += 1
            self.consecutive_connections_to_same_service += 1
        else:
            self.consecutive_connections_to_different_services += 1

        if is_error:
            self.total_connections_with_error += 1
            if service == self.last_service:
                self.connections_to_same_service_with_error += 1
        
        if is_rejected:
            self.total_connections_rejected += 1
            if service == self.last_service:
                self.connections_to_same_service_rejected += 1
        
        if service not in self.hosts_per_service:
            self.hosts_per_service[service] = set()
        if host not in self.hosts_per_service[service]:
            self.hosts_per_service[service].add(host)
            if service == self.last_service:
                self.connections_to_same_service_from_diff_hosts += 1

        self.last_service = service
        self.last_host = host

    def calculate_metrics(self):
        serror_rate = (self.total_connections_with_error / self.total_connections) if self.total_connections > 0 else 0.0
        srv_serror_rate = (self.connections_to_same_service_with_error / self.total_connections_to_same_service) if self.total_connections_to_same_service > 0 else 0.0
        rerror_rate = (self.total_connections_rejected / self.total_connections) if self.total_connections > 0 else 0.0
        srv_rerror_rate = (self.connections_to_same_service_rejected / self.total_connections_to_same_service) if self.total_connections_to_same_service > 0 else 0.0
        same_srv_rate = (self.consecutive_connections_to_same_service / self.total_connections) if self.total_connections > 0 else 0.0
        diff_srv_rate = (self.consecutive_connections_to_different_services / self.total_connections) if self.total_connections > 0 else 0.0
        srv_diff_host_rate = (self.connections_to_same_service_from_diff_hosts / self.total_connections_to_same_service) if self.total_connections_to_same_service > 0 else 0.0

        return {
            "count": self.total_connections,
            "srv_count": self.total_connections_to_same_service,
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": srv_rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
        }

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.session_data = defaultdict((self.initialize_session))
        self.packet_rate = defaultdict(int)
        self.packet_attributes = {}
        self.other_attributes = {}
        self.packet_history = defaultdict(list)
        self.packet_history_time_window = timedelta(seconds=60)

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

        self.producer = KafkaProducer(
            bootstrap_servers=["localhost:9092"],
            retries=3,
            max_block_ms=5000,
            value_serializer=lambda value: json.dumps(value).encode('utf-8'),
            batch_size=32000,
        )


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

        self.protocol_traffic_volume = {"TCP": 0, "UDP": 0, "Other": 0}

    def avro_serializer(data):
        bytes_writer = io.BytesIO()
        writer(bytes_writer , schema  , [data])
        return bytes_writer.getvalue()

    def determine_state(self,packet):
        """Determines the connection state based on TCP flags."""
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x01:  # FIN
                return "FIN"
            elif tcp_flags & 0x04:  # RST
                return "RST"
            elif tcp_flags & 0x02:  # SYN
                return "SYN"
            elif tcp_flags & 0x10:  # ACK
                return "ACK"
        return "UNKNOWN"

    def GetBasicFeatures(self, packet):
        """Extracts basic features from a packet."""
        if IP not in packet:
            logging.warning("Packet does not contain an IP layer.")
            return None
        session_key = (packet[IP].src, packet[IP].dst, packet[IP].sport, packet[IP].dport)
        self.packet_attributes = {
            "id": self.packet_count,
            "proto": packet[IP].proto,
            "service": self.port_to_service.get(packet.dport, "Unknown") if TCP in packet or UDP in packet else "Unknown",
            "state": self.determine_state(packet),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
            "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
            "protocol": "TCP" if TCP in packet else ("UDP" if UDP in packet else "Other"),
            "timestamp": time(),
            "packet_size": len(packet),
            "ttl": packet[IP].ttl
        }

        if session_key not in self.session_data:
            self.initialize_session(session_key)

        self.session_data[session_key]["last_timestamp"] = self.packet_attributes["timestamp"]
        return session_key

    def initialize_session(self, session_key):
        self.session_data[session_key] = {
                "spkts": 0,
                "sbytes": 0,
                "sttl": 0,
                "swin": 0,
                "stcpb": 0,
                "smean": 0,
                "dpkts": 0,
                "dbytes": 0,
                "dttl": 0,
                "dwin": 0,
                "dtcpb": 0,
                "dmean": 0,
                "ct_srv_src": 0,
                "tcprtt": 0,
                "syn_timestamp": 0,
                "synack_timestamp": 0,
                "ack_timestamp": 0,
                "data_timestamp": 0,
                "trans_depth": 0,
                "response_body_len": 0,
                "timestamps_dst": [],
                "first_timestamp": self.packet_attributes.get("timestamp", 0),
                "last_timestamp": self.packet_attributes.get("timestamp", 0),
                "packet_history": [],
                "sinpkt": 0,
                "dinpkt": 0,
                "timestamps_src": [],
                "timestamps_dst_full": [],
                "sjit": 0,
                "djit": 0,
                "ct_state_ttl": 0,      
                "ct_dst_ltm": 0,        
                "ct_src_dport_ltm": 0,   
                "ct_dst_sport_ltm": 0,   
                "ct_dst_src_ltm": 0,     
                "is_ftp_login": False,  
                "ct_ftp_cmd": 0,   
                "ct_flw_http_mthd": 0,    
                "attack_cat" : "Normal"
        }

    def track_packet_history(self, session_key, packet):
        current_time = time()
        session_history = self.packet_history[session_key]

        session_history.append(self.packet_attributes.copy())

        self.packet_history[session_key] = [
            p for p in session_history if current_time - p["timestamp"] <= self.packet_history_time_window.total_seconds()
        ]

    def calculate_loads(self, session_key):
        """
        Calculate sload and dload for a session.
        """
        session = self.session_data[session_key]
        
        duration = session["last_timestamp"] - session["first_timestamp"]
        logging.info(f"duration : {duration}")
        if duration <= 0:
            session["sload"] = 0
            session["dload"] = 0
        else:
            session["sload"] = session["sbytes"] / duration
            session["dload"] = session["dbytes"] / duration
        
        self.packet_attributes.update({
            "sload" : session["sload"],
            "dload" : session["dload"],
        })
        
    def GetPacketRelatedFeatures(self, session_key, packet):
        if session_key not in self.session_data:
            self.initialize_session(session_key)
        session = self.session_data[session_key]

        session["last_timestamp"] = self.packet_attributes["timestamp"]


        self.state_ttl_counter[(self.packet_attributes["state"], self.packet_attributes["ttl"])] += 1
        self.dst_ltm_counter[self.packet_attributes["dst_ip"]].append(self.packet_attributes["timestamp"])
        self.src_dport_ltm_counter[(self.packet_attributes["src_ip"], self.packet_attributes["dst_port"])].append(self.packet_attributes["timestamp"])
        self.dst_sport_ltm_counter[(self.packet_attributes["dst_ip"], self.packet_attributes["src_port"])].append(self.packet_attributes["timestamp"])
        self.dst_src_ltm_counter[(self.packet_attributes["src_ip"], self.packet_attributes["dst_ip"])].append(self.packet_attributes["timestamp"])

        if packet[IP].src == self.packet_attributes["src_ip"]:
            session["timestamps_src"].append(self.packet_attributes["timestamp"])
            session["spkts"] += 1
            session["sbytes"] += self.packet_attributes["packet_size"]
            session["sttl"] = self.packet_attributes["ttl"]

            if packet.haslayer(TCP):
                session["swin"] = packet[TCP].window
                session["stcpb"] += max(len(packet[TCP].payload), 0)
            else:
                session["swin"] = session.get("swin", 0)

            session["smean"] = session["sbytes"] / max(session["spkts"], 1)

            if len(session["timestamps_src"]) > 1:
                inter_arrival_times = [
                    t2 - t1 for t1, t2 in zip(session["timestamps_src"][:-1], session["timestamps_src"][1:])
                ]
                session["sinpkt"] = sum(inter_arrival_times) / len(inter_arrival_times)

                if len(inter_arrival_times) > 1:
                    deviations = [
                        abs(inter_arrival_times[i] - inter_arrival_times[i - 1])
                        for i in range(1, len(inter_arrival_times))
                    ]
                    session["sjit"] = sum(deviations) / len(deviations)
            
            session["ct_state_ttl"] = self.packet_attributes["ttl"]

            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                if "USER" in payload or "PASS" in payload:
                    session["is_ftp_login"] = True
                session["ct_ftp_cmd"] = payload if "USER" in payload or "PASS" in payload else session["ct_ftp_cmd"]

        if packet[IP].dst == self.packet_attributes["dst_ip"]:
            session["timestamps_dst_full"].append(self.packet_attributes["timestamp"])
            session["dpkts"] += 1
            session["dbytes"] += self.packet_attributes["packet_size"]
            session["dttl"] = self.packet_attributes["ttl"]

            if packet.haslayer(TCP):  
                session["dwin"] = packet[TCP].window
                session["dtcpb"] += max(len(packet[TCP].payload), 0)
            else:
                session["dwin"] = session.get("dwin", 0)

            session["dmean"] = session["dbytes"] / max(session["dpkts"], 1)
            session["timestamps_dst"].append(self.packet_attributes["timestamp"])

            if len(session["timestamps_dst_full"]) > 1:
                inter_arrival_times = [
                    t2 - t1 for t1, t2 in zip(session["timestamps_dst_full"][:-1], session["timestamps_dst_full"][1:])
                ]
                session["dinpkt"] = sum(inter_arrival_times) / len(inter_arrival_times)

                if len(inter_arrival_times) > 1:
                    deviations = [
                        abs(inter_arrival_times[i] - inter_arrival_times[i - 1])
                        for i in range(1, len(inter_arrival_times))
                    ]
                    session["djit"] = sum(deviations) / len(deviations)

            session["ct_dst_ltm"] = self.packet_attributes["timestamp"]

            if packet.haslayer(TCP):
                session["ct_src_dport_ltm"] = packet[TCP].sport
            
            if packet.haslayer(TCP):
                session["ct_dst_sport_ltm"] = packet[TCP].dport
            
            session["ct_dst_src_ltm"] = session["ct_dst_sport_ltm"] if packet.haslayer(TCP) else session["ct_dst_src_ltm"]

            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                if "GET" in payload or "POST" in payload or "PUT" in payload or "DELETE" in payload:
                    session["ct_flw_http_mthd"] = payload.split()[0]


        session["sloss"] = max(0, session["spkts"] - session["dpkts"])
        session["dloss"] = max(0, session["dpkts"] - session["spkts"])


        if packet.haslayer(TCP):
            session["tcprtt"] = session.get("tcprtt", 0)
            session["synack"] = session.get("synack", 0)
            session["ackdat"] = session.get("ackdat", 0)

            if "syn_timestamp" in session and "synack_timestamp" in session:
                session["tcprtt"] = session["synack_timestamp"] - session["syn_timestamp"]

            if "syn_timestamp" in session and "synack_timestamp" not in session:
                if packet[TCP].flags == "SA":  # SYN-ACK
                    session["synack_timestamp"] = self.packet_attributes["timestamp"]
                    session["synack"] = session["synack_timestamp"] - session["syn_timestamp"]

            if "data_timestamp" in session and "ack_timestamp" not in session:
                if packet[TCP].flags == "A":  # ACK
                    session["ack_timestamp"] = self.packet_attributes["timestamp"]
                    session["ackdat"] = session["ack_timestamp"] - session["data_timestamp"]

        trans_depth = 0
        content_length = 0
        if packet.haslayer(HTTP):
            if packet[HTTP].Method in ["GET", "POST"]:
                session["trans_depth"] += 1
                trans_depth += session["trans_depth"]
        if packet.haslayer(HTTPResponse):
            if "Content-Length" in packet[HTTPResponse].headers:
                content_len = int(packet[HTTPResponse].headers["Content-Length"])
                session["response_body_len"] = content_len
            elif packet.haslayer(TCP) and packet[TCP].payload:
                session["response_body_len"] = len(packet[TCP].payload)

        session["ct_srv_src"] += 1
        session["smean"] = session["sbytes"] / max(session["spkts"], 1)
        session["dmean"] = session["dbytes"] / max(session["dpkts"], 1)

        self.packet_attributes.update({
            "dur": session["last_timestamp"] - session["first_timestamp"],
            "spkts": session["spkts"],
            "sbytes": session["sbytes"],
            "sttl": session["sttl"],
            "swin": session.get("swin", 0),
            "stcpb": session.get("stcpb", 0),
            "smean": session["smean"],
            "dpkts": session["dpkts"],
            "dbytes": session["dbytes"],
            "dttl": session["dttl"],
            "dwin": session.get("dwin", 0),
            "dtcpb": session.get("dtcpb", 0),
            "dmean": session["dmean"],
            "ct_srv_src": session["ct_srv_src"],
            "response_body_len": session.get("response_body_len", 0),
            "tcprtt": session.get("tcprtt", 0),
            "trans_depth"  : session.get("trans_depth" , 0),
            "tcprtt": session.get("tcprtt", 0),  
            "synack": session.get("synack", 0),  
            "ackdat": session.get("ackdat", 0),
            "sloss": session["sloss"],
            "dloss": session["dloss"],
            "sinpkt": session["sinpkt"],
            "dinpkt": session["dinpkt"],
            "sjit": session["sjit"],
            "djit": session["djit"],
            "ct_state_ttl": session["ct_state_ttl"],
            "ct_dst_ltm": session["ct_dst_ltm"],
            "ct_src_dport_ltm": session["ct_src_dport_ltm"],
            "ct_dst_sport_ltm": session["ct_dst_sport_ltm"],
            "ct_dst_src_ltm": session["ct_dst_src_ltm"],
            "is_ftp_login": session["is_ftp_login"],
            "ct_ftp_cmd": session["ct_ftp_cmd"],
            "ct_flw_http_mthd": session["ct_flw_http_mthd"],
        })

        self.track_packet_history(session_key, packet)

    def update_session_data(self, session_key, features , packet, current_time):
        if session_key not in self.session_data:
            self.session_data[session_key].update({
                "first_timestamp": features["timestamp"],
                "last_timestamp": features["timestamp"]
            })

        session = self.session_data[session_key]
        session["last_timestamp"] = features["timestamp"]
        session["spkts"] += 1
        session["sbytes"] += features["packet_size"]
        session["sttl"] = features["ttl"]
        session["smean"] = session["sbytes"] / max(session["spkts"], 1)

        if packet.haslayer(TCP):
            session["swin"] = packet[TCP].window
            session["stcpb"] += max(len(packet[TCP].payload), 0)

        self.packet_history[session_key].append(features)
        self.packet_history[session_key] = [
            p for p in self.packet_history[session_key]
            if features["timestamp"] - p["timestamp"] <= self.packet_history_time_window.total_seconds()
        ]

        session["packet_history"].append({"timestamp": current_time, "size": len(packet)})


    def avroSerializer(self,data):
        bytes_writer =  BytesIO.IO()
        schema = load_schema(os.getenv('AVRO_SCHEMA_PATH'))
        


    def CalculateTimeMetrics(self, packet, session_key):
        """
        Calculate metrics: ct_src_ltm, ct_srv_dst, is_sm_ips_ports, attack_cat, label based on packet data.
        This function now handles previous packets for a given session.
        """
        if session_key not in self.session_data:
            self.initialize_session(session_key)

        session = self.session_data[session_key]
        history = self.packet_history[session_key]
        current_time = self.packet_attributes["timestamp"]

        for pkt in history:
            src_ip, dst_ip = pkt["src_ip"], pkt["dst_ip"]
            src_port, dst_port = pkt["src_port"], pkt["dst_port"]
            self.src_ltm_counter[src_ip] += 1
            self.srv_dst_counter[src_ip].add(dst_port)
            self.ips_ports_counter[(src_ip, src_port)].add(dst_ip)

        for ip in self.src_ltm_counter:
            session["ct_src_ltm"] = self.src_ltm_counter[ip]
            session["ct_srv_dst"] = len(self.srv_dst_counter[ip])
            session["is_sm_ips_ports"] = "Yes" if len(self.ips_ports_counter.get((ip, 80), [])) < 5 else "No"
            session["attack_cat"] = self.attack_category[ip]
            session["label"] = self.label.get(ip, "Normal")

        self.packet_attributes.update({
            "ct_src_ltm" : session["ct_src_ltm"],
            "ct_srv_dst" : session["ct_srv_dst"],
            "is_sm_ips_ports" : session["is_sm_ips_ports"],
            "attack_cat" : session["attack_cat"],
            "label"  : session["label"],
        })

    def calculate_packet_rate(self, session_key, current_time):
        """Calculate the rate of packets per second within the time window."""
        session = self.session_data[session_key]
        recent_packets = [
            p for p in session["packet_history"]
            if current_time - p["timestamp"] <= TIME_WINDOW.total_seconds()
        ]
        session["packet_history"] = recent_packets  
        return len(recent_packets) / TIME_WINDOW.total_seconds()

    def CalculateFttpMetrics(self, packet, session_key):
        """
        Calculate FTP metrics: is_ftp_login and ct_ftp_cmd based on packet data.
        """
        session = self.session_data[session_key]
        history = self.packet_history[session_key]

        for pkt in history:
            if pkt['protocol'] == 'FTP':
                ftp_cmd = pkt.get('ct_ftp_cmd', '') 
                if ftp_cmd in self.ftp_commands:  
                    ftp_cmd_counter[ftp_cmd] += 1  
                    if ftp_cmd == 'USER' or ftp_cmd == 'PASS':  
                        ftp_login_counter[pkt['src_ip']] = True  

        session["ct_ftp_cmd"] = sum(ftp_cmd_counter.values())  
        session["is_ftp_login"] = any(ftp_login_counter.values())  

        for cmd, count in ftp_cmd_counter.items():
            print(f"FTP command '{cmd}' count: {count}")


    def CalculateHttpMetrics(self,packet,session_key):
        """
        Calculate HTTP metrics: ct_flw_http_mthd based on packet data.
        """
        session = self.session_data[session_key]
        history = self.packet_history[session_key]
        
        for packet in history:
            if packet['protocol'] == 'HTTP':
                http_method = packet['http_method']  
                if http_method in http_methods:
                    self.http_method_counter[http_method] += 1  
        for method, count in self.http_method_counter.items():
            packet['ct_flw_http_mthd'] += count
        
        self.packet_attributes.update({
            "ct_flw_http_mthd" : packet['ct_flw_http_mthd']
        })

    def ProcessDate(self,unix_time):
        date_time = datetime.datetime.fromtimestamp(unix_time)
        res  = date_time.strftime('%Y-%m-%d %H:%M:%S')
        return  res

    def avro_serializer(self,data):
        bytes_writer = io.BytesIO()
        schema = os.getenv('AVRO_SCHEMA_PATH')
        writer(bytes_writer , schema  , [data])
        return bytes_writer.getvalue()

    def Call_Async_producer_sent_packet_data(self, data):
        def on_success(record_metadata):
            logging.info(f"Message sent to topic: {record_metadata.topic}, offset: {record_metadata.offset}")

        def on_error(excp):
            logging.error('Error sending message to Kafka', exc_info=excp)

        try:
            self.producer.send(topic=os.getenv('TOPIC'), value=data).add_callback(on_success).add_errback(on_error)
        except KafkaError as ke:
            logging.error(f"Error sending message to Kafka: {ke}")

    def Call_Async_producer_sent_location_data(self, data):
        def on_success(record_metadata):
            logging.info(f"Message sent to topic: {record_metadata.topic}, offset: {record_metadata.offset}")

        def on_error(excp):
            logging.error('Error sending message to Kafka', exc_info=excp)

        try:
            self.producer.send(topic=os.getenv('PACKET_LOCATION_TOPIC'), value=data).add_callback(on_success).add_errback(on_error)
        except KafkaError as ke:
            logging.error(f"Error sending message to Kafka: {ke}")

    # def __del__(self):
    #     self.producer.close()

    def process_packet(self,packet):
        try:
            if IP not in packet:
                logging.warning("Packet does not contain an IP layer.")
                return

            self.packet_count += 1
            self.packet_attributes.update({
                "id" : self.packet_count,
                "timestamp": time(),
                "packet_size" : len(packet)
            })
                
            session_key = self.GetBasicFeatures(packet)
            current_time = time()

                
            self.GetPacketRelatedFeatures(session_key,packet)
            self.update_session_data(session_key, self.packet_attributes, packet, current_time)
            self.CalculateTimeMetrics(packet , session_key )
            packet_rate = self.calculate_packet_rate(session_key, current_time)
            self.calculate_loads(session_key)

            self.packet_attributes.update({
                "rate" : packet_rate,
            })

            if TCP in packet:
                self.packet_attributes.update({
                    "state" : self.determine_state(packet)
                })
            else:
                D

            src_port = None
            dst_port = None

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            if src_port == 21 or dst_port == 21:
                self.CalculateFttpMetrics(packet , session_key)
            if src_port == 80 or dst_port == 80 or self.packet_attributes.get("service") == "HTTP":
                self.CalculateHttpMetrics(packet ,session_key)

            # if(self.Check_missing_params()):
            #     return

            self.other_attributes = self.network_metrics.process_packet(packet , current_time , self.network_metrics)

            location_data = {
                    "City": "",
                    "Region": "",
                    "Country": "",
                    "latitude": "",
                    "longitude": "",
                }

            if (self.other_attributes.get("src_ip_geolocation") and self.other_attributes["src_ip_geolocation"].get("city") and self.other_attributes["src_ip_geolocation"].get("country") ):
                location_data = {
                    "City": self.other_attributes["src_ip_geolocation"]["city"],
                    "Region": self.other_attributes["src_ip_geolocation"]["region"],
                    "Country": self.other_attributes["src_ip_geolocation"]["country"],
                    "latitude": self.other_attributes["src_ip_geolocation"]["latitude"],
                    "longitude": self.other_attributes["src_ip_geolocation"]["longitude"],
                }

                
                self.Call_Async_producer_sent_location_data(location_data)
            
            self.packet_attributes.update({
                "src_location_info" : location_data,
            })

            location_data = {
                    "City": "",
                    "Region": "",
                    "Country": "",
                    "latitude": "",
                    "longitude": "",
                }

            if ( self.other_attributes.get("dst_ip_geolocation") and self.other_attributes["dst_ip_geolocation"].get("city") and self.other_attributes["dst_ip_geolocation"].get("country") ):        
                location_data = {
                    "City": self.other_attributes["dst_ip_geolocation"]["city"],
                    "Region": self.other_attributes["dst_ip_geolocation"]["region"],
                    "Country": self.other_attributes["dst_ip_geolocation"]["country"],
                    "latitude": self.other_attributes["dst_ip_geolocation"]["latitude"],
                    "longitude": self.other_attributes["dst_ip_geolocation"]["longitude"],
                }

                self.Call_Async_producer_sent_location_data(location_data)

            self.packet_attributes.update({
                "dst_location_info" : location_data,
            })

            print("packets data : ",self.packet_attributes)

            if all(key in self.packet_attributes for key in ["id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports", "label"]):
                self.Call_Async_producer_sent_packet_data(self.packet_attributes)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    @staticmethod
    def Get_Interface():
        print("Checking for Network Interfaces...")

        interfaces = psutil.net_if_addrs()
        print("Available Network Interfaces:", list(interfaces.keys()))

        for index, (iface_name, iface_addresses) in enumerate(interfaces.items(), start=1):
            print(f"\nInterface {index}: {iface_name}")
            for addr in iface_addresses:
                print("Address:", addr.address)

        try:
            user_device_option = int(input("\nChoose an option by index: ")) - 1
            selected_iface = list(interfaces.keys())[user_device_option]
            print(f"You selected: {selected_iface}")
            return selected_iface
        except (ValueError, IndexError):
            print("Invalid option chosen.")
            return "invalid"

    def is_valid_interface(self,iface_name):
        iface_stats = psutil.net_if_stats().get(iface_name)
        iface_addrs = psutil.net_if_addrs().get(iface_name, [])

        if iface_stats and iface_stats.isup:
            if any(addr.address for addr in iface_addrs if addr.family == socket.AF_INET):
                return True
        return False

    def Check_missing_params(self):
        all_cols = ("id","dur","proto","service","state","spkts","dpkts","sbytes","dbytes","rate","sttl","dttl","sload","dload","sloss","dloss","sinpkt","dinpkt","sjit","djit","swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat","smean","dmean","trans_depth","response_body_len","ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst","is_sm_ips_ports","label")
        for col in all_cols:
            if col not in self.packet_attributes.keys():
                return True
        return False


    def sniffer(self):
        selected_iface = self.Get_Interface()
        self.network_metrics = NetworkMetrics()
        
        if selected_iface != "invalid" and self.is_valid_interface(selected_iface):
            print(f"Interface '{selected_iface}' is valid for packet sniffing.")
        else:
            print(f"Interface '{selected_iface}' is not valid for packet sniffing. Sniffing on default interface.\n")
            selected_iface = None

        if selected_iface:
            print(f"Sniffing packets from {selected_iface} :")
            sniff(iface=selected_iface, prn= lambda pkt : self.process_packet(pkt), store=0, count=5 , filter = "ip or tcp or udp" , timeout=10)
        else:
            print("Sniffing packets from default interface:")
            sniff(prn=lambda pkt : self.process_packet(pkt), store=0, count=5 , filter = "ip or tcp or udp" , timeout=50)

if __name__ == "__main__":
    pack_sniff = PacketSniffer()
    pack_sniff.sniffer()
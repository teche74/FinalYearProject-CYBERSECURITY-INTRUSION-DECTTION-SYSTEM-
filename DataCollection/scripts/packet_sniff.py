import psutil
from scapy.all import *
import math
import json
import socket
import geoip2.database
import time
import requests
from kafka import KafkaProducer

city_reader = geoip2.database.Reader("data_collected\Geolite2_databases\GeoLite2-City.mmdb")

connections = {}
sessions = {}

RATE_TIME_WINDOW = 1  ## Track RPS for every 1 second

protocol_traffic_volume = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Kafka producer setup
# producer = KafkaProducer(
#     bootstrap_servers=['localhost:9092'],  # Adjust to your Kafka server
#     value_serializer=lambda v: json.dumps(v).encode('utf-8')
# )

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

def is_valid_interface(iface_name):
    iface_stats = psutil.net_if_stats().get(iface_name)
    iface_addrs = psutil.net_if_addrs().get(iface_name, [])

    if iface_stats and iface_stats.isup:
        if any(addr.address for addr in iface_addrs if addr.family == socket.AF_INET):
            return True
    return False

def process_tcp_packet(packet , current_time, network_metrics):
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
            "payload_entropy": calculate_entropy(bytes(packet[TCP].payload)) if len(packet[TCP].payload) > 0 else None
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
    print(json.dumps(packet_data, indent=4))
    return packet_data

def process_udp_packet(packet, current_time , network_metrics):
    packet_data = {}
    if UDP in packet:
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
            "udp_checksum_valid": verify_udp_checksum(packet[IP], packet[UDP]) 
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

    print(json.dumps(packet_data, indent=4))
    return packet_data

def process_other_packet(packet, current_time , network_metrics):
    packet_data = {}
    if IP in packet and not (TCP in packet or UDP in packet): 
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
            "payload_entropy": calculate_entropy(bytes(packet[IP].payload)) if len(packet[IP].payload) > 0 else None
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
    print(json.dumps(packet_data, indent=4))
    return packet_data

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

def process_packet(packet, network_metrics):
    current_time = time.time()

    if IP in packet:
        if TCP in packet:
            tcp_processed = process_tcp_packet(packet, current_time, network_metrics)
            # producer.send('tcp_packet', tcp_processed)
            with open(r'data_collected\packet_data\tcp_packets.json', 'a') as f:  # Using raw string
                json.dump(tcp_processed, f, indent=4)
                print("tcp packets collected and saved to 'data_collected\\packet_data\\tcp_packets.json'.")

        elif UDP in packet:
            udp_processed = process_udp_packet(packet, current_time, network_metrics)
            # producer.send('udp_packet', udp_processed)
            with open(r'data_collected\packet_data\udp_packet.json', 'a') as f:  # Using raw string
                json.dump(udp_processed, f, indent=4)
                print("udp packets collected and saved to 'data_collected\\packet_data\\udp_packet.json'.")

        else:
            other_processed = process_other_packet(packet, current_time, network_metrics)
            # producer.send('other_packet', other_processed)  
            with open(r'data_collected\packet_data\other_packets.json', 'a') as f:  # Using raw string
                json.dump(other_processed, f, indent=4)
                print("other packets collected and saved to 'data_collected\\packet_data\\other_packets.json'.")  

    
def get_geolocation(ip_address):
    try:
        response = city_reader.city(ip_address)
        return {
            "city": response.city.name,
            "region": response.subdivisions.most_specific.name,
            "country": response.country.name,
            "continent": response.continent.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude
        }
    except Exception as e:
        return None

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
        protocol_traffic_volume["TCP"] += 1
    elif proto == 17:  # UDP
        protocol_traffic_volume["UDP"] += 1
    elif proto == 1:  # ICMP
        protocol_traffic_volume["ICMP"] += 1
    else:
        protocol_traffic_volume["Other"] += 1
    return protocol_traffic_volume


def detect_ip_anomalies(src_ip, dst_ip):
    """Detect IP anomalies (e.g., multiple requests from same source)."""
    current_time = time.time()
    src_count = sessions.get(src_ip, {"count": 0, "timestamp": current_time})["count"]
    sessions[src_ip] = {"count": src_count + 1, "timestamp": current_time}
    return src_count > 100

def check_retransmission(packet):
    """Check if this packet is a retransmission."""
    if hasattr(packet, 'TCP') and packet[TCP].flags == "R": 
        return True
    return False




def run_packet_sniffer():
    print("Packet Sniffer:")

    selected_iface = Get_Interface()
    
    network_metrics = NetworkMetrics()

    if selected_iface != "invalid" and is_valid_interface(selected_iface):
        print(f"Interface '{selected_iface}' is valid for packet sniffing.")
    else:
        print(f"Interface '{selected_iface}' is not valid for packet sniffing. Sniffing on default interface.\n")
        selected_iface = None

    if selected_iface:
        print(f"Sniffing packets from {selected_iface} :")
        sniff(iface=selected_iface, prn= lambda pkt : process_packet(pkt, network_metrics), store=0, count=80)
    else:
        print("Sniffing packets from default interface:")
        sniff(prn=lambda pkt : process_packet(pkt, network_metrics), store=0, count=80)


def main():
    run_packet_sniffer()


if __name__ == "__main__":
    main()
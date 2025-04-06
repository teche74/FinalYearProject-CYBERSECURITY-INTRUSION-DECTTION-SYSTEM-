from scapy.all import sniff, PcapWriter, PcapReader
import threading
import os
import datetime

def process_pcap_file(pcap_file):
    """
    Continuously reads and processes packets from a pcap file.
    :param pcap_file: Path to the pcap file being written.
    """
    print(f"Starting to process packets from {pcap_file}...")
    try:
        while True:
            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                with PcapReader(pcap_file) as pcap_reader:
                    for packet in pcap_reader:
                        print(f"Processing packet: {packet.summary()}")
                        # Example: Add custom processing logic here
            else:
                print("No packets to process yet...")
    except KeyboardInterrupt:
        print("\nStopped processing the pcap file.")

def sniff_and_store(output_file):
    """
    Sniffs packets in real-time and writes them to a pcap file.
    :param output_file: Path to the pcap file to save packets.
    """
    print(f"Starting packet sniffing. Saving to {output_file}...")
    pcap_writer = PcapWriter(output_file, append=True, sync=True)

    def write_packet(packet):
        pcap_writer.write(packet)

    try:
        sniff(prn=write_packet)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.")
    finally:
        pcap_writer.close()

def main():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"realtime_sniff_{timestamp}.pcap"

    processor_thread = threading.Thread(target=process_pcap_file, args=(pcap_file,), daemon=True)
    processor_thread.start()

    sniff_and_store(pcap_file)

if __name__ == "__main__":
    main()

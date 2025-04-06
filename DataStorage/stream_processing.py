import logging
from datetime import datetime
from dotenv import load_dotenv
from astrapy import  *
import os
import sys
from quixstreams import StreamReader, StreamWriter, KafkaStreamingClient
from astrapy.client import create_astra_client

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_table(client):
    try:
        query = """
        CREATE TABLE IF NOT EXISTS data_packets (
            id INT PRIMARY KEY,
            proto INT,
            service TEXT,
            state TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INT,
            dst_port INT,
            protocol TEXT,
            timestamp TIMESTAMP,
            packet_size INT,
            ttl INT,
            duration FLOAT,
            spkts INT,
            sbytes INT,
            sttl INT,
            swin INT,
            stcpb INT,
            smean FLOAT,
            dpkts INT,
            dbytes INT,
            dttl INT,
            dwin INT,
            dtcpb INT,
            dmean FLOAT,
            ct_srv_src INT,
            response_body_len INT,
            tcprtt FLOAT,
            trans_depth INT,
            synack FLOAT,
            ackdat FLOAT,
            sloss INT,
            dloss INT,
            sinpkt FLOAT,
            dinpkt FLOAT,
            sjit FLOAT,
            djit FLOAT,
            ct_state_ttl INT,
            ct_dst_ltm TIMESTAMP,
            ct_src_dport_ltm INT,
            ct_dst_sport_ltm INT,
            ct_dst_src_ltm INT,
            is_ftp_login BOOLEAN,
            ct_ftp_cmd TEXT,
            ct_flw_http_mthd TEXT,
            ct_src_ltm INT,
            ct_srv_dst INT,
            is_sm_ips_ports TEXT,
            label TEXT,
            sload FLOAT,
            dload FLOAT,
            rate FLOAT
        )
        """
        client.cql(query)
        logging.info("Table created successfully.")
    except Exception as e:
        logging.error(f"Error creating table: {e}")

def insert_data(client, record):
    try:
        query = """
        INSERT INTO data_packets (
            id, proto, service, state, src_ip, dst_ip, src_port, dst_port, protocol, timestamp,
            packet_size, ttl, duration, spkts, sbytes, sttl, swin, stcpb, smean, dpkts, dbytes,
            dttl, dwin, dtcpb, dmean, ct_srv_src, response_body_len, tcprtt, trans_depth, synack,
            ackdat, sloss, dloss, sinpkt, dinpkt, sjit, djit, ct_state_ttl, ct_dst_ltm,
            ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd,
            ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports, label,
            sload, dload, rate
        ) VALUES (
            %(id)s, %(proto)s, %(service)s, %(state)s, %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s, %(protocol)s, %(timestamp)s,
            %(packet_size)s, %(ttl)s, %(duration)s, %(spkts)s, %(sbytes)s, %(sttl)s, %(swin)s, %(stcpb)s, %(smean)s, %(dpkts)s, %(dbytes)s,
            %(dttl)s, %(dwin)s, %(dtcpb)s, %(dmean)s, %(ct_srv_src)s, %(response_body_len)s, %(tcprtt)s, %(trans_depth)s, %(synack)s,
            %(ackdat)s, %(sloss)s, %(dloss)s, %(sinpkt)s, %(dinpkt)s, %(sjit)s, %(djit)s, %(ct_state_ttl)s, %(ct_dst_ltm)s,
            %(ct_src_dport_ltm)s, %(ct_dst_sport_ltm)s, %(ct_dst_src_ltm)s, %(is_ftp_login)s, %(ct_ftp_cmd)s,
            %(ct_flw_http_mthd)s, %(ct_src_ltm)s, %(ct_srv_dst)s, %(is_sm_ips_ports)s, %(label)s,
            %(sload)s, %(dload)s, %(rate)s
        )
        """
        client.cql(query, record)
        logging.info("Data inserted successfully.")
    except Exception as e:
        logging.error(f"Could not insert data: {e}")

def kafka_to_cassandra():
    try:
        secure_connect_bundle = os.getenv('ASTRA_DB_SECURE_BUNDLE_PATH')
        kafka_broker = os.getenv('KAFKA_BROKER_URL')
        topic = os.getenv('TOPIC')

        if not secure_connect_bundle or not kafka_broker or not topic:
            logging.error("Required environment variables are not set.")
            return

        client = create_astra_client(secure_connect_bundle=secure_connect_bundle)
        create_table(client)

        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=kafka_broker,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )

        for message in consumer:
            record = message.value
            record['timestamp'] = datetime.now() 
            insert_data(client, record)
    except Exception as e:
        logging.error(f"Error in kafka_to_cassandra: {e}")
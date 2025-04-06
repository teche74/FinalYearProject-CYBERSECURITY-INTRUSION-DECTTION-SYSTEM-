from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from kafka import KafkaConsumer
import logging
import json
import os
import subprocess
from dotenv import load_dotenv
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'DataStorage')))

from stream_processing import kafka_to_cassandra

load_dotenv()


default_args = {
    'owner': 'ujjwal',
    'start_date': datetime(2024, 11, 14, 9, 36),
    'retries': 2,
    'email_on_failure': False,
    'email_on_retry': False,
    'retry_delay': timedelta(minutes=5),
}

dag =  DAG( 
    'threat_detection_pipeline', 
    default_args=default_args,
    description='A DAG to run sniffer, extract data from kafka topic and store it to cassandra, and visualize in Grafana',
    schedule = timedelta(minutes=5),
    catchup=False, 
)


def run_sniffer():
    logging.info("Python Sniffer started !!")
    script_path = os.getenv('SNIFFER_PATH')
    subprocess.run(["python3" , script_path] , check = True)


run_sniffer_task = PythonOperator(
    task_id = "run_sniffer_script",
    python_callable = run_sniffer,
    dag = dag,
) 


kafka_to_cassandra_task = PythonOperator(
    task_id="kafka_to_cassandra",
    python_callable=kafka_to_cassandra,
    dag=dag,
)

def run_log_collector():
    logging.info("Running log collector...")
    log_collector_path = os.getenv('LOG_COLLECTOR_PATH')
    subprocess.run(["python3", log_collector_path], check=True)

run_log_collector_task = PythonOperator(
    task_id='run_log_collector',
    python_callable=run_log_collector,
    dag=dag,
)

def run_dashboard():
    script_path = OS.GETENV('DASHBOARD_PATH')
    subprocess.run(["python3" , script_path] , check = True)


trigger_dashboard_task = PythonOperator(
    task_id='trigger_dashboard_visualization',
    python_callable=run_dashboard,
    dag=dag,
)

run_sniffer_task >> kafka_to_cassandra_task >> run_log_collector_task >> trigger_dashboard_task
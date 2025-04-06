import os
import re
import subprocess
import requests
import pandas as pd
import plotly.express as px
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify , Response,stream_with_context
from flask_caching import Cache
from dotenv import load_dotenv
import random
from flask_session import Session
import plotly.graph_objects as go  
from kafka import KafkaConsumer
import json
import threading
import time
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
import logging
import atexit 
import signal
import smtplib
import requests
import yagmail
import numpy as np
from flask_cors import cross_origin
from datetime import datetime
import openai

logging.basicConfig(
    filename="C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/IDS logging info/dashboard.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


load_dotenv()
LOGS_DIR = os.getenv('LOGS_DIR')

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getenv('DASH_PATH'), 'sessions')
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
Session(app)

openai.api_key = os.getenv("API_KEY")

sent_alerts = set()
latest_location_data_from_kafka= [] 
# zookeeper_process = None
# kafka_process = None
consumer2 = None

system_prompt = os.getenv('SYSTEM_PROMPT', """You are a cybersecurity AI expert specializing in Intrusion Detection Systems (IDS). 
You help users understand security threats, anomalies, and solutions in a simple, accurate way. 
Provide detailed responses with examples, best practices, and preventive measures. 
Avoid overly technical jargon unless necessary.
""")

users = {
    'admin': os.getenv('DASH_PASS1'),
    'user': os.getenv('DASH_PASS2')
}

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/')
@cross_origin(supports_credentials=True)
def index():
    """Redirect to the login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def login():
    """Login page for user authentication."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username] == password:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html' )


@app.route('/map')
@cross_origin()
def map():
    """Route to display map data."""
    try:
        return render_template('map.html')
    except Exception as e:
        flash(f"Error loading map: {str(e)}", 'danger')
        return render_template('map.html')

@app.route('/stream')
@cross_origin()
def stream():
    def generate():
        while True:
            yield f"data: {json.dumps(latest_location_data_from_kafka or [])}\n\n"
            time.sleep(5) 

    return Response(generate(), mimetype='text/event-stream')

def fetch_latest_packet_data():
    """Fetch the latest packet data from Kafka or another source."""
    KAFKA_TOPIC = os.getenv('PACKET_LOCATION_TOPIC')
    KAFKA_SERVERS = ["localhost:9092"]

    try:
        consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_SERVERS,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )

        global latest_location_data_from_kafka

        for message in consumer:
            latest_location_data_from_kafka.append(message.value)
            if len(latest_location_data_from_kafka) > 10:
                latest_location_data_from_kafka.pop(0)
            

    except Exception as e:
        logging.error(f"Error fetching data from Kafka: {e}")

@app.route("/attacks", methods=["GET"])
@cross_origin()
def get_attack_data():
    KAFKA_TOPIC = os.getenv('ANOMALY_TOPIC')
    KAFKA_SERVERS = ["localhost:9092"]
    attack_data_list = []
    print("topic : ",KAFKA_TOPIC)

    try:
        consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_SERVERS,
            auto_offset_reset='earliest',              
            enable_auto_commit=False,  
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            group_id= "attack-consumer" 
        )

        messages = consumer.poll(timeout_ms=5000)
        consumer.seek_to_beginning()

        if not messages:
            print("data not reached .. ")
            return jsonify([]) 

        for partition in messages.values():
            for record in partition:
                print("data : ",record.value)
                attack_data_list.append(record.value)

        if messages:
            consumer.commit()

    except Exception as e:
        return jsonify([])

    finally:
        consumer.close() 

    return jsonify(attack_data_list)


# @app.route('/dashboard')
# @cross_origin(supports_credentials=True)
# def dashboard():
#     """Main page displaying dashboard."""
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     logs = running_process_log_extractor()
    
#     if logs.empty:
#         flash('No logs available to display.', 'warning')
    
#     logs['Date'] = datetime.now()
#     limited_logs = logs.tail(10)  
    
#     if 'Date' in limited_logs.columns:
#         limited_logs['Date'] = limited_logs['Date'].dt.strftime('%Y-%m-%d %H:%M:%S')

#     bar_chart = px.bar(logs, x="Image Name", y="Mem Usage", color="Session Name")
#     bar_chart.update_layout(
#         xaxis_title="Process Name",  
#         yaxis_title="Memory Usage (MB)",
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)',  
#     )

#     pie_chart = px.sunburst(
#         logs,
#         path=["Session Name", "Image Name"],
#         values="Mem Usage",
#         color="Session Name",
#         color_discrete_sequence=px.colors.qualitative.Bold,
#         hover_data={"Image Name": True, "Session Name": True, "Mem Usage": ":.2f"}
#     ) 
#     pie_chart.update_layout(
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',
#         plot_bgcolor='rgba(0, 0, 0, 0)',  
#     )

#     most_memory_intensive = logs.sort_values(by='Mem Usage', ascending=False).head(5)
#     bar_chart2 = px.bar(most_memory_intensive, 
#         x="Image Name", 
#         y="Mem Usage", 
#         color="Session Name",
#         labels={'Image Name': 'Process Name', 'Mem Usage': 'Memory Usage (KB)', 'Session Name': 'Session'}
#     )
#     bar_chart2.update_layout(
#         xaxis_title="Process Name",  
#         yaxis_title="Memory Usage (MB)",
#         margin=dict(t=10, b=10, l=10, r=10),  
#         paper_bgcolor='rgba(0, 0, 0, 0)',     
#         plot_bgcolor='rgba(0, 0, 0, 0)',       
#     )

#     network_data = network_connections_log_extractor()
#     protocol_counts = network_data['Protocol'].value_counts()

#     protocol_pie_chart = go.Figure(data=[go.Pie(labels=protocol_counts.index, values=protocol_counts, hole=0.3)])
#     protocol_pie_chart.update_layout(
#         title="Distribution of Active Connections by Protocol",
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)',  
#     )

#     line_chart = px.line(logs, x='Date', y='Mem Usage', color='Session Name')
#     line_chart.update_layout(
#         xaxis_title="Timestamp",
#         yaxis_title="Memory Usage (MB)",
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)',  
#     )


#     network_state_count = network_data['State'].value_counts()
#     new_state_bar_chart = go.Figure(data=[go.Bar(x=network_state_count.index, y=network_state_count)])

#     new_state_bar_chart.update_layout(
#         yaxis_title="Count",
#         xaxis_title="Connection State",
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)',  
#     )

#     address_counts = network_data.groupby(['Local Address', 'Foreign Address']).size().reset_index(name='Counts')
#     address_bar_chart = px.bar(address_counts, x='Local Address', y='Counts', color='Foreign Address')
#     address_bar_chart.update_layout(
#         yaxis_title="Count",
#         xaxis_title="Connection State",
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)',  
#     )

#     network_data['Local Port'] = network_data['Local Address'].str.split(':').str[1]
#     listening_ports = network_data['Local Port'].value_counts().head(10)
#     listening_ports_bar_chart = go.Figure(data=[go.Bar(x=listening_ports.index, y=listening_ports)])
#     listening_ports_bar_chart.update_layout(
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)', 
#     )


#     firewall_data = firewall_log_extractor()
#     firewall_data['datetime'] = pd.to_datetime(firewall_data['date'] + ' ' + firewall_data['time'])
#     traffic_volume = firewall_data.groupby([firewall_data['datetime'], 'protocol']).size().reset_index(name='traffic_volume')
#     traffic_volume['hour'] = traffic_volume['datetime'].dt.floor('h')  
#     traffic_volume_hourly = traffic_volume.groupby(['hour', 'protocol'])['traffic_volume'].sum().reset_index()
#     traffic_over_time_chart = px.line(traffic_volume_hourly, 
#                                     x='hour', 
#                                     y='traffic_volume', 
#                                     color='protocol')

#     traffic_over_time_chart.update_layout(
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)',  
#         plot_bgcolor='rgba(0, 0, 0, 0)', 
#         xaxis_title='Time',
#         yaxis_title='Traffic Volume',
#         legend_title='Protocol',
#         showlegend=True,
#     )

#     action_distribution = firewall_data['action'].value_counts().reset_index(name='count')
#     action_distribution.columns = ['action', 'count']

#     action_chart = px.pie(action_distribution, names='action', values='count')

#     action_chart.update_layout(
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)', 
#         plot_bgcolor='rgba(0, 0, 0, 0)',   
#     )

#     firewall_data['size'] = pd.to_numeric(firewall_data['size'], errors='coerce')
#     firewall_data['size_mb'] = firewall_data['size'] / (1024 * 1024)
#     top_source_ips = firewall_data.groupby('src-ip')['size_mb'].sum().reset_index().sort_values('size_mb', ascending=False).head(10)
#     top_source_ips_chart = px.bar(
#         top_source_ips,
#         x='src-ip',
#         y='size_mb',
#         labels={'size_mb': 'Traffic Volume (MB)', 'src-ip': 'Source IP'}
#     )

#     top_source_ips_chart.update_layout(
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)', 
#         plot_bgcolor='rgba(0, 0, 0, 0)',
#     )


#     top_dest_ips = firewall_data.groupby('dst-ip')['size'].sum().reset_index().sort_values('size', ascending=False).head(10)

#     top_dest_ips_chart = px.bar(top_dest_ips, x='dst-ip', y='size')
#     top_dest_ips_chart.update_layout(
#         margin=dict(t=10, b=10, l=10, r=10),
#         paper_bgcolor='rgba(0, 0, 0, 0)', 
#         plot_bgcolor='rgba(0, 0, 0, 0)',
#     )




#     return render_template(
#         'index.html', 
#         bar_chart=bar_chart.to_html(full_html=False),
#         pie_chart=pie_chart.to_html(full_html=False),
#         bar_chart2=bar_chart2.to_html(full_html=False),
#         line_chart = line_chart.to_html(full_html = False),
#         protocol_pie_chart=protocol_pie_chart.to_html(full_html=False),
#         network_bar = new_state_bar_chart.to_html(full_html = False),
#         address_bar_chart = address_bar_chart.to_html(full_html = False),
#         listening_ports_bar_chart = listening_ports_bar_chart.to_html(full_html = False),
#         traffic_over_time_chart = traffic_over_time_chart.to_html(full_html = False),
#         allow_deny_chart = action_chart.to_html(full_html= False),
#         top_source_ips_chart = top_source_ips_chart.to_html(full_html = False),
#         top_dest_ips_chart = top_dest_ips_chart.to_html(full_html = False),

#         logs=limited_logs.to_dict(orient='records')
#     )




@app.route('/dashboard')
@cross_origin(supports_credentials=True)
def dashboard():
    """Main page displaying dashboard with empty chart containers."""
    if 'username' not in session:
        return redirect(url_for('login'))

    logs = running_process_log_extractor()
    if logs.empty:
        flash('No logs available to display.', 'warning')
    
    logs['Date'] = datetime.now()
    limited_logs = logs.tail(10)
    
    if 'Date' in limited_logs.columns:
        limited_logs['Date'] = limited_logs['Date'].dt.strftime('%Y-%m-%d %H:%M:%S')

    return render_template('index.html', logs=limited_logs.to_dict(orient='records'))

@app.route('/get_chart_data')
@cross_origin(supports_credentials=True)
def get_chart_data():
    """Return JSON data for updating charts continuously."""
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    logs = running_process_log_extractor()
    if logs.empty:
        return jsonify({
            "bar_chart": {"x": [], "y": [], "color": []},
            "pie_chart": {"labels": [], "values": []},
            "line_chart": {"x": [], "y": [], "color": []},
            "protocol_pie_chart": {"labels": [], "values": []},
            "network_bar": {"x": [], "y": []},
            "address_bar_chart": {"x": [], "y": [], "color": []},
            "listening_ports_bar_chart": {"x": [], "y": []},
            "traffic_over_time_chart": {"x": [], "y": [], "color": []},
            "allow_deny_chart": {"labels": [], "values": []},
            "top_source_ips_chart": {"x": [], "y": []},
            "top_dest_ips_chart": {"x": [], "y": []},
            "bar_chart2": {"x": [], "y": [], "color": []}
        })

    logs['Date'] = datetime.now()

    # print(logs)

    bar_chart_data = {
        "x": logs["Image Name"].tolist(),
        "y": logs["Mem Usage"].tolist(),
        "color": logs["Session Name"].tolist()
    }
    # print("bar data : ", bar_chart_data)
    pie_chart_data = {
        "labels": logs["Session Name"].tolist(),
        "values": logs["Mem Usage"].tolist()
    }
    # print("pie data : ", pie_chart_data)

    line_chart_data = {
        "x": logs["Date"].astype(str).tolist(),
        "y": logs["Mem Usage"].tolist(),
        "color": logs["Session Name"].tolist()
    }

    network_data = network_connections_log_extractor()
    if not network_data.empty and 'Protocol' in network_data.columns:
        protocol_counts = network_data['Protocol'].value_counts()
        protocol_pie_data = {
            "labels": protocol_counts.index.tolist(),
            "values": protocol_counts.tolist()
        }
    else:
        protocol_pie_data = {"labels": [], "values": []}

    # print("protocol data : ", protocol_pie_data)

    # Network Connection State Distribution
    network_state_chart_data = {"x": [], "y": []}
    if not network_data.empty and 'State' in network_data.columns:
        network_state_count = network_data['State'].value_counts()
        network_state_chart_data = {
            "x": network_state_count.index.tolist(),
            "y": network_state_count.tolist()
        }

    # Address Bar Chart (Local & Foreign Address Counts)
    address_bar_chart_data = {"x": [], "y": [], "color": []}
    if not network_data.empty and 'Local Address' in network_data.columns:
        address_counts = network_data.groupby(['Local Address', 'Foreign Address']).size().reset_index(name='Counts')
        address_bar_chart_data = {
            "x": address_counts['Local Address'].tolist(),
            "y": address_counts['Counts'].tolist(),
            "color": address_counts['Foreign Address'].tolist()
        }

    # Listening Ports Chart (Top 10)
    listening_ports_chart_data = {"x": [], "y": []}
    if not network_data.empty and 'Local Address' in network_data.columns:
        network_data['Local Port'] = network_data['Local Address'].str.split(':').str[1]
        listening_ports = network_data['Local Port'].value_counts().head(10)
        listening_ports_chart_data = {
            "x": listening_ports.index.tolist(),
            "y": listening_ports.tolist()
        }

    # Firewall Logs (Traffic Over Time)
    firewall_data = firewall_log_extractor()
    if 'datetime' not in firewall_data.columns:
        firewall_data['datetime'] = datetime.now()

    traffic_over_time_chart_data = {"x": [], "y": [], "color": []}
    if not firewall_data.empty and 'date' in firewall_data.columns and 'time' in firewall_data.columns:
        firewall_data['datetime'] = pd.to_datetime(firewall_data['date'] + ' ' + firewall_data['time'])
        traffic_volume = firewall_data.groupby([firewall_data['datetime'], 'protocol']).size().reset_index(name='traffic_volume')
        traffic_volume['hour'] = traffic_volume['datetime'].dt.floor('h')
        traffic_volume_hourly = traffic_volume.groupby(['hour', 'protocol'])['traffic_volume'].sum().reset_index()
        traffic_over_time_chart_data = {
            "x": traffic_volume_hourly['hour'].astype(str).tolist(),
            "y": traffic_volume_hourly['traffic_volume'].tolist(),
            "color": traffic_volume_hourly['protocol'].tolist()
        }

    # Allowed vs Denied Requests Chart
    
    # 📌 Firewall Logs Processing (Action Trends Over Time)
    # 📌 Ensure "ALLOW" and "DENY" columns exist in grouped data
    action_trends = firewall_data.groupby([firewall_data['datetime'].dt.floor('h'), 'action']).size().unstack(fill_value=0)

    # Ensure "DENY" column exists (if missing, add it with 0 values)
    if "DENY" not in action_trends.columns:
        action_trends["DENY"] = 0  # ✅ Add zero values for missing DENY actions

    # Reset index to make datetime available as a column
    action_trends.reset_index(inplace=True)

    # Prepare data for frontend
    allow_deny_trend_chart_data = {
        "x": action_trends['datetime'].astype(str).tolist(),
        "allow_values": action_trends["ALLOW"].tolist(),
        "deny_values": action_trends["DENY"].tolist()  # ✅ Now "DENY" will always exist
    }

    # print("Final Allow vs Deny Data:", allow_deny_trend_chart_data)  # Debugging




    # Top Source & Destination IPs
    top_source_ips_chart_data = {"x": [], "y": []}
    top_dest_ips_chart_data = {"x": [], "y": []}
    if not firewall_data.empty and 'src-ip' in firewall_data.columns:
        firewall_data['size'] = pd.to_numeric(firewall_data['size'], errors='coerce')
        firewall_data['size_mb'] = firewall_data['size'] / (1024 * 1024)
        top_source_ips = firewall_data.groupby('src-ip')['size_mb'].sum().reset_index().sort_values('size_mb', ascending=False).head(10)
        top_source_ips_chart_data = {
            "x": top_source_ips['src-ip'].tolist(),
            "y": top_source_ips['size_mb'].tolist()
        }
    if not firewall_data.empty and 'dst-ip' in firewall_data.columns:
        top_dest_ips = firewall_data.groupby('dst-ip')['size'].sum().reset_index().sort_values('size', ascending=False).head(10)
        top_dest_ips_chart_data = {
            "x": top_dest_ips['dst-ip'].tolist(),
            "y": top_dest_ips['size'].tolist()
        }

    # Most Memory Intensive Processes
    most_memory_intensive = logs.sort_values(by='Mem Usage', ascending=False).head(5)
    bar_chart2_data = {
        "x": most_memory_intensive["Image Name"].tolist(),
        "y": most_memory_intensive["Mem Usage"].tolist(),
        "color": most_memory_intensive["Session Name"].tolist()
    }

    return jsonify({
        "bar_chart": bar_chart_data,
        "pie_chart": pie_chart_data,
        "line_chart": line_chart_data,
        "protocol_pie_chart": protocol_pie_data,
        "network_bar": network_state_chart_data,
        "address_bar_chart": address_bar_chart_data,
        "listening_ports_bar_chart": listening_ports_chart_data,
        "traffic_over_time_chart": traffic_over_time_chart_data,
        "allow_deny_trend_chart": allow_deny_trend_chart_data,
        "top_source_ips_chart": top_source_ips_chart_data,
        "top_dest_ips_chart": top_dest_ips_chart_data,
        "bar_chart2": bar_chart2_data
    })

@app.route('/logout')
@cross_origin(supports_credentials=True)
def logout():
    """Logout the user."""
    session.pop('username', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))



def check_suspicious_process_names(df, suspicious_paths=None, random_name_threshold=10):
    """
    Check for suspicious process names based on naming patterns and file paths.

    Parameters:
        df (pd.DataFrame): DataFrame containing process information.
        suspicious_paths (list): List of paths considered unusual for legitimate processes.
        random_name_threshold (int): Minimum length of a name to consider it as a random name.

    Returns:
        list: List of alerts for suspicious processes.
    """
    if suspicious_paths is None:
        suspicious_paths = [
            r"C:\\Windows\\Temp\\",
            r"C:\\Users\\[^\\]+\\AppData\\",
            r"C:\\Temp\\"
        ]

    alerts = []

    for index, row in df.iterrows():
        process_name = row.get('Image Name', '').lower()
        pid = row.get('PID', 'Unknown')
        session = row.get('Session#', 'Unknown')

        if len(process_name) >= random_name_threshold and re.match(r"^[a-z0-9]+$", process_name):
            alerts.append(f"Suspicious process detected (random name): {row['Image Name']} (PID: {pid}) in Session {session}")

        for path in suspicious_paths:
            if re.match(path, row.get('Image Path', '')):
                alerts.append(f"Suspicious process detected (unusual location): {row['Image Name']} (PID: {pid}) in Session {session}")
                break

    return alerts


def check_high_memory_usage(df, memory_threshold=80.0):
    """
    Check for processes exceeding a defined memory usage threshold.

    Parameters:
        df (pd.DataFrame): DataFrame containing process information.
        memory_threshold (float): Percentage memory usage to trigger alerts.

    Returns:
        list: List of alerts for high memory usage.
    """
    alerts = []

    for index, row in df.iterrows():
        try:
            memory_usage = float(row.get('Mem Usage', 0))
            process_name = row.get('Image Name', 'Unknown')
            pid = row.get('PID', 'Unknown')
            session = row.get('Session#', 'Unknown')

            if memory_usage > memory_threshold:
                alerts.append(f"High memory usage detected: {memory_usage}% by {process_name} (PID: {pid}) in Session {session}")
        except (ValueError, TypeError):
            continue

    return alerts

def check_process_with_virustotal(process_name):
    url = f'https://www.virustotal.com/api/v3/files/{process_name}'
    
    headers = {
        'x-apikey': os.getenv('VT_API_KEY')
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            if json_response['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                return True
    except requests.RequestException as e:
        logging.info(f"Error checking VirusTotal for {process_name}: {e}")
    
    return False

def check_abnormal_sessions(df, threshold_factor=1.5):
    """
    Detect abnormal session activity dynamically based on statistical analysis.

    Parameters:
        df (pd.DataFrame): DataFrame containing process information, including 'Session#'.
        threshold_factor (float): Factor for determining outliers based on the IQR method.

    Returns:
        list: List of alerts for abnormal session activities.
    """
    alerts = []

    if 'Session#' not in df.columns:
        raise ValueError("'Session#' column is missing from the DataFrame")
    
    session_counts = df['Session#'].value_counts()

    q1 = np.percentile(session_counts, 25)
    q3 = np.percentile(session_counts, 75)
    iqr = q3 - q1
    lower_bound = q1 - threshold_factor * iqr
    upper_bound = q3 + threshold_factor * iqr

    abnormal_sessions = session_counts[(session_counts < lower_bound) | (session_counts > upper_bound)].index

    for index, row in df.iterrows():
        session_number = row['Session#']
        if session_number in abnormal_sessions:
            alerts.append(f"Abnormal session activity: {row['Image Name']} (PID: {row['PID']}) in Session {session_number}")
            logging.error(f"Abnormal session activity: {row['Image Name']} (PID: {row['PID']}) in Session {session_number}")

    return alerts

def send_alert(alerts):
    global sent_alerts
    new_alerts = [alert for alert in alerts if alert not in sent_alerts]
    
    if not new_alerts:
        logging.info("No new alerts to send.")
        return
    
    def send_email_alerts(alerts, recipient_email, sender_email, sender_password):

        """
        Send email notifications for alerts.

        Parameters:
            alerts (list): List of alert messages to send.
            recipient_email (str): The recipient's email address.
            sender_email (str): The sender's email address.
            sender_password (str): The sender's email password (e.g., app password for Gmail).
        """
        if not alerts:
            logging.info("No alerts to send.")
            return

        try:
            yag = yagmail.SMTP(user=sender_email, password=sender_password)
            subject = "System Alert Notification"
            body = "\n".join(alerts)
            yag.send(to=recipient_email, subject=subject, contents=body)
            logging.info(f"Email sent successfully to {recipient_email}")
        except Exception as e:
            logging.info(f"Failed to send email. Error: {type(e).__name__} - {e}")

        except Exception as e:
            logging.info(f"Failed to send email. Error: {type(e).__name__} - {e}")

    def send_telegram_alerts(alerts, bot_token, chat_id):
        """
        Send Telegram notifications for alerts.

        Parameters:
            alerts (list): List of alert messages to send.
            bot_token (str): Telegram bot token obtained from BotFather.
            chat_id (str): Telegram chat ID of the recipient.
        """
        if not alerts:
            logging.info("No alerts to send.")
            return

        try:
            message = "\n".join([alert.strip() for alert in alerts if alert.strip()])

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": alerts
            }

            response = requests.post(url, data=payload)
            if response.status_code == 200:
                logging.info("Telegram alert sent successfully.")
            else:
                logging.info(f"Failed to send Telegram alert: {response.text}")
            
        except Exception as e:
            logging.info(f"Error sending Telegram alert: {e}")
    
    # send_email_alerts(alerts, os.getenv('RECEIVER_MAIL'), os.getenv('SENDER_MAIL'),  os.getenv('SENDER_PASS'))
    send_telegram_alerts(alerts, os.getenv('TELE_BOT_API_TOKEN'), os.getenv('TELE_CHAT_ID'))
    sent_alerts.update(new_alerts)

def analyze_logs(df):
    """Function to analyze the logs for suspicious processes, high memory usage, and abnormal sessions."""
    suspicious_processes = check_suspicious_process_names(df)
    high_memory_alerts = check_high_memory_usage(df)
    abnormal_session_alerts = check_abnormal_sessions(df)

    alerts = suspicious_processes + high_memory_alerts + abnormal_session_alerts

    if alerts:
        for alert in alerts:
            send_alert(alert)
    else:
        logging.info("No suspicious activities detected.")


def application_event_log_extractor(start_position):
    """
    Parse the detailed log file without using regular expressions, starting from the last read position.
    
    Args:
        start_position (int): The last position read in the log file.

    Returns:
        tuple: A tuple containing a list of structured event logs and the new position to resume from.
    """
    app_event_log = os.path.join(LOGS_DIR, 'Application_event_logs.txt')

    if not os.path.exists(app_event_log):
        logging.info(f"App event log file not found at: {app_event_log}. Please check the path.")
        return [], start_position

    try:
        with open(app_event_log, 'r', encoding='utf-8') as file:
            structured_events = []
            current_event = {}
            inside_event = False
            collecting_multiline = False
            multiline_key = None
            multiline_value = []
            problem_signature = {} 
            attached_files = []  

            file.seek(start_position)

            for line in file:
                line = line.strip()

                if line.startswith("Event["): 
                    if current_event:  
                        if problem_signature:
                            current_event["Problem signature"] = problem_signature
                        if attached_files:
                            current_event["Attached files"] = attached_files
                        structured_events.append(current_event)

                    current_event = {"Event Number": line}
                    inside_event = True
                    collecting_multiline = False
                    multiline_key = None
                    multiline_value = []
                    problem_signature = {}
                    attached_files = []

                elif inside_event and ":" in line:  
                    if collecting_multiline:
                        if multiline_key == "Attached files":
                            attached_files.extend(multiline_value)
                        else:
                            current_event[multiline_key] = "\n".join(multiline_value).strip()
                        collecting_multiline = False
                        multiline_key = None
                        multiline_value = []

                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    if key.startswith("P") and key[1:].isdigit():  
                        problem_signature[key] = value
                    elif key == "Attached files":  
                        collecting_multiline = True
                        multiline_key = "Attached files"
                        multiline_value = [value] if value else []
                    elif key == "These files may be available here":
                        current_event["These files may be available here"] = value
                    else:
                        current_event[key] = value

                elif collecting_multiline:
                    if line.startswith(r"\\\\?\\C"):  
                        multiline_value.append(line)
                    else:
                        collecting_multiline = False
            if problem_signature:
                current_event["Problem signature"] = problem_signature
            if attached_files:
                current_event["Attached files"] = attached_files
            if current_event:
                structured_events.append(current_event)

            new_position = file.tell()

        return structured_events, new_position

    except Exception as e:
        logging.info(f"An error occurred while processing the log file: {e}")
        return [], start_position


def send_logs_to_kafka(events):
    """
    Sends log data to a Kafka topic.

    Args:
        events (list): List of log dictionaries to send.
    """
    KAFKA_BROKER = ['localhost:9092']  
    KAFKA_TOPIC = os.getenv('SIGN_TOPIC_IDS')  

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )

    for event in events:
        logging.info(f"Event : {event}")
        try:
            producer.send(KAFKA_TOPIC, event)
            logging.info(f"Sent event to Kafka: {event}")
        except Exception as e:
            logging.error(f"Failed to send event to Kafka: {e}")

    producer.flush()
    producer.close()


def monitor_log_file():
    """
    Monitors the log file for new events and sends them to Kafka.
    """
    last_position = 0

    while True:
        events, last_position = application_event_log_extractor(last_position)

        if events:
            send_logs_to_kafka(events)  

        time.sleep(60)


def firewall_log_extractor():
    """
    Extracts firewall firewall_data from a given text file and returns structured data.
    The firewall_data will be in the format of a list of dictionaries, with each dictionary containing the log's fields.
    
    Returns:
        list: A list of dictionaries containing the structured log data.
    """
    firewall_data = []
    log_file = os.path.join(LOGS_DIR, 'firewall_logs.txt')
    
    if not os.path.exists(LOGS_DIR):
        logging.info(f"Log file not found at: {LOGS_DIR}. Please check the LOGS_DIR path.")
        return pd.DataFrame()

    try:
        with open(log_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line.startswith("#Fields"):
                    fields = line.split(":")[1].strip().split()
                    break

            for line in file:
                line = line.strip()
                if line:
                    log_parts = line.split()

                    if len(log_parts) == len(fields):
                        log_entry = {fields[i]: log_parts[i] for i in range(len(fields))}
                        firewall_data.append(log_entry)
        return pd.DataFrame(firewall_data)

    except Exception as e:
        logging.info(f"An error occurred while processing the log file: {e}")
        return pd.DataFrame()

def network_connections_log_extractor():
    """
    Extracts network connection data from a log file and returns it as a DataFrame.
    """
    network_data = []
    log_file = os.path.join(LOGS_DIR, 'network_connections.txt')
    
    if not os.path.exists(LOGS_DIR):
        logging.info(f"Log file not found at: {LOGS_DIR}. Please check the LOGS_DIR path.")
        return pd.DataFrame()

    try:
        with open(log_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        cleaned_lines = [
            line.strip() for line in lines 
            if line.strip() and not re.match(r'={5,}', line)  
        ]

        patterns = [
            re.compile(r'^\s*(TCP|UDP)\s+([\[\d.:]+)\s+([\[\d.:]*)\s+(\S+)?\s+(\d+)?$'),
            re.compile(r'^\s*UDP\s+([\[\d.:]+)\s+(\*:\*)\s+(\d+)$'),
            re.compile(r'^\s*UDP\s+\[([0-9a-fA-F:]+)\]\s+(\*:\*)\s+(\d+)$'),
            re.compile(r'^\s*(TCP|UDP)\s+(\[.*?\]:\d+|\d+.\d+.\d+.\d+:\d+)\s+(\[.*?\]:\d+|\*:\*|\d+.\d+.\d+.\d+:\d+)?\s+(\S+)?\s+(\d+)?$'),
            re.compile(r"UDP\s+\[(.*?)\]:([\d]+)\s+\*:\*\s+([\d]+)")
        ]

        for line in cleaned_lines[3:]:
            for pattern in patterns:
                match = pattern.match(line.strip())
                if match:
                    network_data.append({
                        'Protocol': match.group(1) if match.lastindex >= 1 else 'UDP', 
                        'Local Address': match.group(2) if match.lastindex >= 2 else 'N/A',
                        'Foreign Address': match.group(3) if match.lastindex >= 3 else 'N/A',
                        'State': match.group(4) if match.lastindex >= 4 else 'N/A',
                        'PID': int(match.group(5)) if match.lastindex >= 5 and match.group(5) else None
                    })
                    break  
        df = pd.DataFrame(network_data)
        return df

    except Exception as e:
        logging.info(f"An error occurred while extracting data: {e}")
        return pd.DataFrame()



def running_process_log_extractor():
    """Extract running process data from a log file and return as a DataFrame."""
    process_data = []    

    if not os.path.exists(LOGS_DIR):
        logging.info(f"Log file not found at: {LOGS_DIR}. Please check the LOGS_DIR path.")
        return pd.DataFrame()

    try:
        with open(os.path.join(LOGS_DIR, 'running_processes.txt'), 'r', encoding='utf-8') as file:
            lines = file.readlines()
            
        pattern = r"(.*?)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+\s*[KMG]?)"

        for line in lines[1:]:
            match = re.search(pattern, line)
            if match:
                columns = [
                    match.group(1).strip(),
                    int(match.group(2)),
                    match.group(3).strip(),
                    int(match.group(4)),
                    match.group(5).strip()
                ]
                process_data.append(columns)

        df = pd.DataFrame(process_data, columns=["Image Name", "PID", "Session Name", "Session#", "Mem Usage"])

        df["Mem Usage"] = df["Mem Usage"].apply(convert_memory_usage)

        analyze_logs(df)

        return df

    except FileNotFoundError:
        logging.info("Log file not found. Please check the LOGS_DIR path.")
        return pd.DataFrame() 

@app.route('/get_logs')
@cross_origin(supports_credentials=True)
def get_logs():
    process_logs = pd.DataFrame(running_process_log_extractor())
    
    random_logs = process_logs.sample(n=10 , replace=False)
    
    return jsonify(random_logs.to_dict(orient='records'))


def convert_memory_usage(mem_usage):
    """Convert memory usage string to an integer value in MB."""
    if 'K' in mem_usage:
        return int(mem_usage.replace(' K', '').replace(',', '')) / 1024  
    elif 'M' in mem_usage:
        return int(mem_usage.replace(' M', '').replace(',', ''))  
    elif 'G' in mem_usage:
        return int(mem_usage.replace(' G', '').replace(',', '')) * 1024  
    return int(mem_usage) 


@app.route('/anomaly_alert', methods=['GET'])
@cross_origin()
def anomaly_alert():
    """Render the anomaly alert page."""
    return render_template('anomaly_alert.html')  


def get_kafka_consumer():
    global consumer2
    if consumer2 is None:
        app.logger.info("Initializing Kafka Consumer...")
        consumer2 = KafkaConsumer(
            os.getenv('ANOMALY_TOPIC'),
            bootstrap_servers=[os.getenv('KAFKA_BROKER_URL')],
            auto_offset_reset='earliest',
            enable_auto_commit=False,
            group_id='anomaly-detector',
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            consumer_timeout_ms=15000
        )
    return consumer2

@app.route('/check-anomalies', methods=['GET', 'POST'])
@cross_origin()
def check_anomalies():
    """Check for anomalies in Kafka messages and return a JSON response."""
    
    topic = os.getenv('ANOMALY_TOPIC')
    broker = os.getenv('KAFKA_BROKER_URL')

    if not topic or not broker:
        return jsonify({"error": "Missing Kafka topic or broker URL!"}), 500

    print(f"Connecting to Kafka: Topic={topic}, Broker={broker}")

    anomalies = []
    try:
        consumer = get_kafka_consumer()  # Reuse the consumer

        for _ in range(10):
            messages = consumer.poll(timeout_ms=500)
            if not messages:
                print("no messages")
                continue

            for _, records in messages.items():
                for message in records:
                    data = message.value
                    print(f"Received Kafka message: {data}")

                    if data.get('is_attack') == 1 and data.get('attack_cat') != 'Generic':
                        anomalies.append(data)

                    if len(anomalies) >= 10:
                        break
            if len(anomalies) >= 10:
                break

    except Exception as e:
        print(f"Error occurred: {e}. Returning no anomalies.")
        return jsonify({"status": "no_anomalies", "anomalies": []})

    return jsonify({"status": "anomaly_detected", "anomalies": anomalies})


@app.route("/chatbot", methods=["POST"])
@cross_origin()
def chatbot():
    user_input = request.json.get("message", "").strip()

    if not user_input:
        return jsonify({"response": "Please ask a relevant question about cybersecurity."})

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_input}
            ]
        )

        bot_reply = response["choices"][0]["message"]["content"]
        return jsonify({"response": bot_reply})

    except Exception as e:
        logging.info(f"Error occurred: {e}")
        return jsonify({"response": "Error connecting to OpenAI. Try again later."})

def stop_services():
    """
    Stops both Zookeeper and Kafka services gracefully.
    """
    if zookeeper_process:
        logging.info("Stopping Zookeeper...")
        os.kill(zookeeper_process.pid, signal.SIGTERM)
        zookeeper_process = None

    if kafka_process:
        logging.info("Stopping Kafka...")
        os.kill(kafka_process.pid, signal.SIGTERM)
        kafka_process = None


def start_services():
    """Start Zookeeper and Kafka services in sequence."""

    ZOOKEEPER_CMD = f"powershell.exe -WindowStyle Hidden Start-Process -NoNewWindow -FilePath '{os.getenv('KAFKA_PATH')}\\bin\\windows\\zookeeper-server-start.bat' '{os.getenv('KAFKA_PATH')}\\config\\zookeeper.properties'"

    KAFKA_CMD = f"powershell.exe -WindowStyle Hidden Start-Process -NoNewWindow -FilePath '{os.getenv('KAFKA_PATH')}\\bin\\windows\\kafka-server-start.bat' '{os.getenv('KAFKA_PATH')}\\config\\server.properties'"
    
    global zookeeper_process, kafka_process
    
    try:
        zookeeper_process = subprocess.Popen(ZOOKEEPER_CMD, shell=True)
        kafka_process = subprocess.Popen(KAFKA_CMD, shell=True)
        
        logging.info("Zookeeper started.")
        logging.info("Kafka started.")
        
        atexit.register(stop_services)
        
    except Exception as e:
        logging.info(f"Error occurred: {e}")



if __name__ == "__main__":
    # threading.Thread(target=start_services, daemon=True).start()
    threading.Thread(target=fetch_latest_packet_data, daemon=True).start()
    threading.Thread(target=monitor_log_file, daemon=True).start()
    app.run(debug=True , port = 5050 , threaded = True)
    
import os
import re
import requests
import pandas as pd
import plotly.express as px
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_caching import Cache
from dotenv import load_dotenv
import random
from flask_session import Session
import plotly.graph_objects as go  
from kafka import KafkaConsumer
import json
from dateutil.parser import parse 
from flask_cors import CORS
import datetime

from dotenv import load_dotenv

load_dotenv()
LOGS_DIR = os.getenv('LOGS_DIR')



# def application_event_log_extractor():
#     """
#     Parse the detailed log file and extract structured data.

#     Returns:
#         list: A list of dictionaries with structured event details.
#     """
#     app_event_log = os.path.join(LOGS_DIR, 'practise.txt')

#     if not os.path.exists(app_event_log):
#         print(f"App event log file not found at: {app_event_log}. Please check the path.")
#         return []

#     try:
#         with open(app_event_log, 'r', encoding='utf-8') as file:
#             log_data = file.read()
        
#         # Regular expression pattern for extracting events
#         event_pattern = re.compile(
#             r"Event\[\d+\]\s*"
#             r"Log Name:\s*(.*?)\s*"
#             r"Source:\s*(.*?)\s*"
#             r"Date:\s*(.*?)\s*"
#             r"Event ID:\s*(\d+)?\s*"
#             r"Task:\s*(.*?)\s*"
#             r"Level:\s*(.*?)\s*"
#             r"Opcode:\s*(.*?)\s*"
#             r"Keyword:\s*(.*?)\s*"
#             r"User:\s*(.*?)\s*"
#             r"User Name:\s*(.*?)\s*"
#             r"Computer:\s*(.*?)\s*"
#             r"Description:\s*(.*?)\s*"
#             r"Fault bucket.*?:\s*(.*?)\s*"
#             r"Event Name:\s*(.*?)\s*"
#             r"Response:\s*(.*?)\s*"
#             r"Cab Id:\s*(.*?)\s*"
#             r"Problem signature:\s*(.*?)\s*"
#             r"Attached files:\s*(.*?)\s*"
#             r"These files may be available here:\s*(.*?)\s*"
#             r"Analysis symbol:\s*(.*?)\s*"
#             r"Rechecking for solution:\s*(.*?)\s*"
#             r"Report Id:\s*(.*?)\s*"
#             r"Report Status:\s*(.*?)\s*"
#             r"Hashed bucket:\s*(.*?)\s*"
#             r"Cab Guid:\s*(.*?)\s*",
#             re.DOTALL
#         )

#         # Apply the pattern on the log data
#         events = event_pattern.findall(log_data)

#         # Process the extracted events into a structured format
#         structured_events = []
#         for event in events:
#             structured_events.append({
#                 "Log Name": event[0].strip(),
#                 "Source": event[1].strip(),
#                 "Date": datetime.fromisoformat(event[2].replace('Z', '+00:00')) if event[2] else None,
#                 "Event ID": int(event[3]) if event[3] else None,
#                 "Task": event[4].strip(),
#                 "Level": event[5].strip(),
#                 "Opcode": event[6].strip(),
#                 "Keyword": event[7].strip(),
#                 "User": event[8].strip(),
#                 "User Name": event[9].strip(),
#                 "Computer": event[10].strip(),
#                 "Description": event[11].strip(),
#                 "Fault bucket": event[12].strip(),
#                 "Event Name": event[13].strip(),
#                 "Response": event[14].strip(),
#                 "Cab Id": event[15].strip(),
#                 "Problem signature": event[16].strip(),
#                 "Attached files": event[17].strip(),
#                 "Available files location": event[18].strip(),
#                 "Analysis symbol": event[19].strip(),
#                 "Rechecking for solution": event[20].strip(),
#                 "Report Id": event[21].strip(),
#                 "Report Status": event[22].strip(),
#                 "Hashed bucket": event[23].strip(),
#                 "Cab Guid": event[24].strip()
#             })

#             print(structured_events[-1])  # Print the last extracted event for debugging

#         print(f"Extracted {len(structured_events)} structured events.")
#         return structured_events

#     except Exception as e:
#         print(f"An error occurred while processing the log file: {e}")
#         return []

import os
from dateutil.parser import parse  


def application_event_log_extractor():
    """
    Parse the detailed log file without using regular expressions.

    Returns:
        list: A list of dictionaries with structured event details.
    """
    app_event_log = os.path.join(LOGS_DIR, 'practise.txt')

    if not os.path.exists(app_event_log):
        print(f"App event log file not found at: {app_event_log}. Please check the path.")
        return []

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

        print(f"Extracted {len(structured_events)} structured events.")
        return structured_events

    except Exception as e:
        print(f"An error occurred while processing the log file: {e}")
        return []




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
        print(f"Log file not found at: {LOGS_DIR}. Please check the LOGS_DIR path.")
        logging.error(f"Log file not found at: {LOGS_DIR}. Please check the LOGS_DIR path.")
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

            

        print(f"Extracted {len(firewall_data)} firewall log entries.")
        return firewall_data

    except Exception as e:
        print(f"An error occurred while processing the log file: {e}")
        return []
def main():
    # events = application_event_log_extractor()
    # for event in events:
    #     print(event)



    data = firewall_log_extractor()
    for val in data:
        print(json.dumps(val , indent =4))


if __name__ == "__main__":
    main()

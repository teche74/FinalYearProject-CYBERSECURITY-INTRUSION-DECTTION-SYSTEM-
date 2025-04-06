import os
import json
import joblib
import pandas as pd
import logging
from config import RF_MODEL_PATH, KNN_MODEL_PATH, SCALER_PATH, FEATURE_COLUMNS, KNN_FEATURE_COLUMNS, ANOMALY_TOPIC, TOPIC, KAFKA_BROKER_URL, SERVICE_MODEL_PATH
from sklearn.preprocessing import LabelEncoder, StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def safe_transform(le, series):
    """
    Safely transform a pandas Series using a LabelEncoder.
    For any value not seen during fitting, assign a default value of -1.
    """
    classes = set(le.classes_)
    return series.apply(lambda x: le.transform([x])[0] if x in classes else -1)

class AttackDetector:
    def __init__(self, test_mode=False):
        """Initialize the attack detector and load models and Kafka if not in test mode."""
        logging.info("Initializing AttackDetector...")

        try:
            self.knn_model = joblib.load(KNN_MODEL_PATH)
            logging.info(f"KNN Model loaded from {KNN_MODEL_PATH}")
        except Exception as e:
            logging.error(f"Failed to load KNN model: {e}")
            self.knn_model = None

        try:
            self.rf_model = joblib.load(RF_MODEL_PATH)
            logging.info(f"RF Model loaded from {RF_MODEL_PATH}")
        except Exception as e:
            logging.error(f"Failed to load RF model: {e}")
            self.rf_model = None

        try:
            self.scaler = joblib.load(SCALER_PATH)
            logging.info(f"Scaler loaded from {SCALER_PATH}")
        except Exception as e:
            logging.error(f"Failed to load scaler: {e}")
            self.scaler = None

        try:
            self.service_model = joblib.load(SERVICE_MODEL_PATH)
            logging.info(f"Service Model loaded from {SERVICE_MODEL_PATH}")
        except Exception as e:
            logging.error(f"Failed to load service model: {e}")
            self.service_model = None

        self.label_encoders = {}
        self.test_mode = test_mode

        if not self.test_mode:
            from kafka import KafkaConsumer, KafkaProducer
            try:
                self.consumer = KafkaConsumer(
                    TOPIC,
                    bootstrap_servers=KAFKA_BROKER_URL,
                    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
                )
                logging.info("Kafka consumer initialized successfully.")

                self.producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BROKER_URL,
                    value_serializer=lambda x: json.dumps(x).encode('utf-8')
                )
                self.producer.bootstrap_connected()
                logging.info("Kafka producer initialized and ready.")
            except Exception as e:
                logging.error(f"Error initializing Kafka: {e}")
                self.consumer, self.producer = None, None

    def preprocess_packet(self, packet_data):
        """Preprocess packet data for the RF model, ensuring service prediction if needed."""
        df = pd.DataFrame([packet_data])
        if "service" in df.columns and df["service"].iloc[0] == "Unknown" and self.service_model is not None:
            df["service"] = self.predict_service(df)
            logging.info(f"Predicted service: {df['service'].iloc[0]}")

        df.replace("Unknown", None, inplace=True)
        df.fillna(0, inplace=True)

        for col in df.select_dtypes(include=['object']).columns:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
            else:
                df[col] = safe_transform(self.label_encoders[col], df[col].astype(str))

        return df

    def predict_service(self, df):
        """Predict the service if it is 'Unknown' using the service prediction model."""
        df_temp = df.copy()
        df_temp["service"] = -1 

        X = df_temp.drop(columns=["service", "attack_cat", "label"], errors="ignore")

        for col in X.select_dtypes(include=['object']).columns:
            X[col] = X[col].astype('category').cat.codes

        predicted_service = self.service_model.predict(X)[0]
        return predicted_service

    def preprocess_for_knn(self, df):
        """Apply encoding and scaling for KNN prediction using a copy of data."""
        df_knn = df.copy()
        for col in ['proto', 'service', 'state']:
            if col in df_knn.columns:
                df_knn[col] = df_knn[col].astype('category').cat.codes

        for col in KNN_FEATURE_COLUMNS:
            if col in df_knn.columns and df_knn[col].dtype == object:
                df_knn[col] = df_knn[col].astype('category').cat.codes

        try:
            df_knn = df_knn[KNN_FEATURE_COLUMNS]
        except KeyError as e:
            missing_cols = list(set(KNN_FEATURE_COLUMNS) - set(df_knn.columns))
            logging.error(f"Missing columns in input data for KNN: {missing_cols}")
            raise e

        if self.scaler is not None:
            try:
                df_knn_scaled = self.scaler.transform(df_knn)
            except Exception as e:
                logging.error(f"Error scaling data: {e}")
                raise e
        else:
            logging.error("Scaler is not loaded. Returning raw features.")
            df_knn_scaled = df_knn.values

        return df_knn_scaled

    def predict_attack_category(self, df):
        """Predict attack category using the KNN model."""
        df_knn = self.preprocess_for_knn(df)
        if df_knn is None or self.knn_model is None:
            return "Unknown"
        predicted_attack_cat = self.knn_model.predict(df_knn)
        logging.info(f"Predicted attack category: {predicted_attack_cat[0]}")
        return predicted_attack_cat[0]

    def predict_attack(self, packet_data):
        """Predict whether a packet contains an attack using the RF model."""
        data = {key: packet_data[key] for key in FEATURE_COLUMNS if key in packet_data}
        df = self.preprocess_packet(data)
        if self.rf_model is None:
            return "Unknown"
        prediction = self.rf_model.predict(df)[0]
        logging.info(f"RF Prediction: {'Attack' if prediction == 1 else 'Normal'}")
        return prediction

    def test_packet(self, packet_data):
        """Test a single packet in standalone mode."""
        logging.info("🔍 Testing single packet...")
        logging.info(f"Packet Data: {packet_data}")
        packet_df = pd.DataFrame([packet_data])
        packet_data["attack_cat"] = self.predict_attack_category(packet_df.copy())
        is_attack = self.predict_attack(packet_data)
        logging.info(f"Final Prediction: {'⚠️ Attack Detected!' if is_attack == 1 else '✅ Normal Traffic'}")

    def listen_and_detect(self):
        """Listen to Kafka topic and detect attacks in real time."""
        if not self.consumer or not self.producer:
            logging.error("Kafka consumer/producer not initialized. Exiting...")
            return

        logging.info("🚀 Listening for network packet data...")
        for message in self.consumer:
            packet_data = dict(message.value)
            logging.info("Received network packet for analysis.")
            packet_df = pd.DataFrame([packet_data])
            packet_data["attack_cat"] = self.predict_attack_category(packet_df.copy())
            is_attack = self.predict_attack(packet_data)
            packet_data.update({"is_attack" : int(is_attack)})
            try:
                future = self.producer.send(ANOMALY_TOPIC, packet_data)
                future.get(timeout=10)
                logging.info("Packet with attack category and prediction sent to Kafka.")
            except Exception as e:
                logging.error(f"Error sending packet to Kafka: {e}")

    def start(self):
        """Start the attack detection system."""
        if self.test_mode:
            logging.info("🔹 Running in standalone test mode. Use `test_packet()` to check samples.")
        else:
            self.listen_and_detect()

if __name__ == "__main__":
    detector = AttackDetector(test_mode=False)
    detector.start()

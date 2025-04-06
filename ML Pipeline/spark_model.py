from pyspark.sql import SparkSession
from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.feature import VectorAssembler, MinMaxScaler, StandardScaler
from pyspark.sql.functions import col
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.tuning import ParamGridBuilder, CrossValidator
from pyspark.ml.evaluation import MulticlassClassificationEvaluator
from sparkxgb import XGBoostClassifier
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

scala_version = '2.12'
spark_version = '3.2.1'
packages = [
    f'org.apache.spark:spark-sql-kafka-0-10_{scala_version}:{spark_version}',
    f'org.apache.spark:spark-streaming-kafka-0-10_{scala_version}:{spark_version}',
    f'org.apache.spark:spark-token-provider-kafka-0-10_{scala_version}:{spark_version}',
    'org.apache.kafka:kafka-clients:2.1.1',
    'org.apache.commons:commons-pool2:2.8.0'
]

def create_spark_session():
    """
    Create a Spark session with the necessary configurations.
    """
    try:
        spark = SparkSession.builder \
            .master("local") \
            .appName("NetworkIntrusionDetection") \
            .config("spark.jars.packages", ",".join(packages)) \
            .getOrCreate()

        spark.sparkContext.setLogLevel('ERROR')
        logging.info("Spark session created successfully.")
        return spark
    except Exception as e:
        logging.error(f"Error creating Spark session: {e}")
        raise

def extract_data_from_kafka(spark):
    """
    Extract data from Kafka and return it as a Spark DataFrame.
    """
    try:
        kafka_df = spark.readStream.format("kafka") \
            .option("kafka.bootstrap.servers", os.getenv('KAFKA_BROKER_URL')) \
            .option("subscribe", os.getenv('TOPIC')) \
            .option("includeHeaders", "true") \
            .option("startingOffsets", "latest") \
            .load()

        parsed_df = kafka_df.selectExpr("CAST(value AS STRING) as json_payload")
        logging.info("Data extracted from Kafka successfully.")
        return parsed_df
    except Exception as e:
        logging.error(f"Error extracting data from Kafka: {e}")
        raise

def preprocess_data(spark_df, feature_columns):
    """
    Preprocess the data by assembling features and applying Min-Max scaling.
    """
    try:
        assembler = VectorAssembler(inputCols=feature_columns, outputCol="features")
        assembled_df = assembler.transform(spark_df)

        minmax_scaler = MinMaxScaler(inputCol="features", outputCol="scaled_features")
        scaler_model = minmax_scaler.fit(assembled_df)
        scaled_df = scaler_model.transform(assembled_df)

        logging.info("Data preprocessing completed successfully.")
        return scaled_df
    except Exception as e:
        logging.error(f"Error during data preprocessing: {e}")
        raise

def train_and_tune_models(processed_df):
    """
    Train and tune Random Forest and XGBoost models using cross-validation.
    """
    try:
        label_col = "label"
        feature_col = "scaled_features"
        
        rf = RandomForestClassifier(labelCol=label_col, featuresCol=feature_col)
        rf_param_grid = ParamGridBuilder() \
            .addGrid(rf.numTrees, [50, 100, 200]) \
            .addGrid(rf.maxDepth, [10, 20, 30]) \
            .build()

        xgb = XGBoostClassifier(labelCol=label_col, featuresCol=feature_col)
        xgb_param_grid = ParamGridBuilder() \
            .addGrid(xgb.maxDepth, [3, 6, 9]) \
            .addGrid(xgb.eta, [0.1, 0.2, 0.3]) \
            .addGrid(xgb.numRound, [50, 100, 200]) \
            .build()

        evaluator = MulticlassClassificationEvaluator(labelCol=label_col, predictionCol="prediction", metricName="accuracy")

        rf_cv = CrossValidator(estimator=rf, estimatorParamMaps=rf_param_grid, evaluator=evaluator, numFolds=3)
        rf_model = rf_cv.fit(processed_df)

        xgb_cv = CrossValidator(estimator=xgb, estimatorParamMaps=xgb_param_grid, evaluator=evaluator, numFolds=3)
        xgb_model = xgb_cv.fit(processed_df)

        logging.info("Model training and tuning completed successfully.")
        return rf_model.bestModel, xgb_model.bestModel
    except Exception as e:
        logging.error(f"Error during model training and tuning: {e}")
        raise

def predict_using_model(model, processed_df):
    """
    Use the trained model to make predictions.
    """
    try:
        predictions = model.transform(processed_df)
        predictions = predictions.select("features", "label", "prediction")
        logging.info("Predictions generated successfully.")
        return predictions
    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        raise


def detect_anomalies(predicted_df, anomaly_class=1):
    """
    Detect anomalies based on the prediction results.
    """
    try:
        anomalies = predicted_df.filter(col("prediction") == anomaly_class)

        if anomalies.count() > 0:
            logging.warning("Anomalies detected:")
            anomalies.show(truncate=False)
            write_to_kafka(anomalies)

        return anomalies
    except Exception as e:
        logging.error(f"Error during anomaly detection: {e}")
        raise

def write_to_kafka(predicted_df):
    """
    Send the predicted data to Kafka.
    """
    try:
        query = predicted_df.selectExpr("to_json(struct(*)) AS value") \
            .writeStream.format("kafka") \
            .option("kafka.bootstrap.servers", os.getenv('KAFKA_BROKER_URL')) \
            .option("topic", os.getenv('ANOMALY_TOPIC')) \
            .outputMode("append") \
            .start()

        query.awaitTermination(timeout=600)
        logging.info("Predicted data written to Kafka successfully.")
    except Exception as e:
        logging.error(f"Error writing data to Kafka: {e}")
        raise

def main():
    try:
        spark = create_spark_session()

        kafka_df = extract_data_from_kafka(spark)

        feature_columns = [
            "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload",
            "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
            "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
            "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
            "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
            "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
        ]

        processed_df = preprocess_data(spark_df, feature_columns)

        # rf_best_model, xgb_best_model = train_and_tune_models(processed_df)

        # rf_predictions = predict_using_model(rf_best_model, processed_df)
        # xgb_predictions = predict_using_model(xgb_best_model, processed_df)

        rf_model = PipelineModel.load("models/random_forest_model")
        xgb_model = PipelineModel.load("models/xgboost_model")

        rf_predictions = rf_model.transform(processed_df)
        xgb_predictions = xgb_model.transform(processed_df)



        logging.info("Analyzing Random Forest predictions for anomalies...")
        detect_anomalies(rf_predictions)

        logging.info("Analyzing XGBoost predictions for anomalies...")
        detect_anomalies(xgb_predictions)

    except Exception as e:
        logging.error(f"An error occurred in the main function: {e}")

if __name__ == "__main__":
    main()

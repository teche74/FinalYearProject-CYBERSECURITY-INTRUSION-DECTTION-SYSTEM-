import os
import pandas as pd
import numpy as np
import joblib
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

TRAIN_DATA_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/DataCollection/data_collected/Training_Testing_Data/UNSW_NB15_training-set.csv"
TEST_DATA_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/DataCollection/data_collected/Training_Testing_Data/UNSW_NB15_testing-set.csv"
MODEL_SAVE_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/ML Pipeline/models/rf_model.pkl"

def load_data(train_path, test_path):
    """Load and concatenate training and testing data."""
    logging.info("Loading data...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    df = pd.concat([train_df, test_df]).drop('id', axis=1).reset_index(drop=True)
    logging.info("Data loaded successfully.")
    return df

def preprocess_data(df):
    """Encode categorical variables and separate features and labels."""
    logging.info("Preprocessing data...")
    for col in ['proto', 'service', 'state']:
        df[col] = df[col].astype('category').cat.codes
    df['attack_cat'] = df['attack_cat'].astype('category')
    X = df.drop(columns=['attack_cat', 'label'])
    y = df['label'].values
    logging.info("Data preprocessing completed.")
    return X, y

def train_model(X, y):
    """Train a RandomForest model and return it."""
    logging.info("Training model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=11)
    model = RandomForestClassifier(random_state=11, n_estimators=100, min_samples_split=5, min_samples_leaf=1)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    logging.info(f"Model Accuracy: {accuracy_score(y_test, y_pred)}")
    logging.info("Classification Report:\n%s", classification_report(y_test, y_pred))
    return model

def save_model(model, path):
    """Save trained model to a file."""
    logging.info("Saving model...")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    logging.info(f"Model saved to {path}")

if __name__ == "__main__":
    df = load_data(TRAIN_DATA_PATH, TEST_DATA_PATH)
    X, y = preprocess_data(df)
    model = train_model(X, y)
    save_model(model, MODEL_SAVE_PATH)

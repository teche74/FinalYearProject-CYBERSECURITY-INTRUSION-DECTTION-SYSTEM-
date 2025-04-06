import os
import pandas as pd
import numpy as np
import joblib
import logging
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TRAIN_DATA_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/DataCollection/data_collected/Training_Testing_Data/UNSW_NB15_training-set.csv"
TEST_DATA_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/DataCollection/data_collected/Training_Testing_Data/UNSW_NB15_testing-set.csv"
MODEL_SAVE_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/ML Pipeline/models/knn_attack_cat_model.pkl"
SCALER_SAVE_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/ML Pipeline/models/knn_scaler.pkl"
LABEL_ENCODER_SAVE_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/ML Pipeline/models/knn_label_encoder.pkl"

def load_data(train_path, test_path):
    """
    Load and concatenate training and testing data.
    Drops the 'id' column if present.
    """
    logging.info("Loading training and testing data...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    df = pd.concat([train_df, test_df]).reset_index(drop=True)
    if 'id' in df.columns:
        df = df.drop('id', axis=1)
    logging.info(f"Data loaded with shape: {df.shape}")
    return df

def preprocess_data(df):
    """
    Preprocess the UNSW NB15 data:
      - Encode common categorical features (e.g. 'proto', 'service', 'state')
      - Encode the target 'attack_cat' using LabelEncoder.
      - Remove unwanted columns ('attack_cat' and optionally 'label') from features.
    """
    logging.info("Preprocessing data...")
    for col in ['proto', 'service', 'state']:
        if col in df.columns:
            df[col] = df[col].astype('category').cat.codes

    if 'attack_cat' not in df.columns:
        raise ValueError("The 'attack_cat' column is missing from the dataset.")

    # Encode attack_cat labels
    label_encoder = LabelEncoder()
    df['attack_cat'] = label_encoder.fit_transform(df['attack_cat'])
    
    y = df['attack_cat']
    drop_cols = ['attack_cat']
    if 'label' in df.columns:
        drop_cols.append('label')
    X = df.drop(columns=drop_cols)
    logging.info(f"Features shape: {X.shape}, Target shape: {y.shape}")
    return X, y, label_encoder

def train_knn_model(X, y):
    """
    Split the data, scale the features, and train a KNN model using GridSearchCV to
    find the best parameters.
    Returns the best KNN estimator and the scaler.
    """
    logging.info("Splitting data into training and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    logging.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    logging.info("Training KNN model with GridSearchCV...")
    param_grid = {
        'n_neighbors': [3, 5, 7, 9, 11],
        'weights': ['uniform', 'distance']
    }
    knn = KNeighborsClassifier()
    grid_search = GridSearchCV(knn, param_grid, cv=5, scoring='accuracy', n_jobs=-1)
    grid_search.fit(X_train_scaled, y_train)
    
    best_knn = grid_search.best_estimator_
    logging.info(f"Best parameters: {grid_search.best_params_}")
    
    y_pred = best_knn.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    logging.info(f"KNN model Accuracy on test set: {acc:.4f}")
    logging.info("Classification Report:\n" + classification_report(y_test, y_pred))
    
    return best_knn, scaler

def save_models(model, scaler, label_encoder, model_path, scaler_path, encoder_path):
    """
    Save the trained KNN model, scaler, and label encoder to disk.
    """
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    logging.info(f"Model saved to {model_path}")
    logging.info(f"Scaler saved to {scaler_path}")
    logging.info(f"Label encoder saved to {encoder_path}")

def main():
    df = load_data(TRAIN_DATA_PATH, TEST_DATA_PATH)
    X, y, label_encoder = preprocess_data(df)
    best_knn, scaler = train_knn_model(X, y)
    save_models(best_knn, scaler, label_encoder, MODEL_SAVE_PATH, SCALER_SAVE_PATH, LABEL_ENCODER_SAVE_PATH)

if __name__ == "__main__":
    main()

import pandas as pd
import joblib
import logging
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

TRAIN_DATA_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/DataCollection/data_collected/Training_Testing_Data/UNSW_NB15_training-set.csv"
MODEL_SAVE_PATH = "C:/Users/ujjwa/Desktop/CyberSec Project/RealTimeNetworkIntrusionDetectionSystem/ML Pipeline/models/service_predictor.pkl"

def load_data(path):
    """Load and clean training data."""
    df = pd.read_csv(path)
    if 'id' in df.columns:
        df = df.drop('id', axis=1)
    return df

def train_service_model(df):
    """Train and evaluate the service prediction model with detailed analysis."""
    logging.info("Training service prediction model...")

    # Encode categorical variables
    label_encoders = {}
    for col in ["proto", "state", "service"]:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

    # Remove rows where service is -1 (previously unknown)
    df = df[df["service"] != -1]

    X = df.drop(columns=["service", "attack_cat", "label"], errors="ignore")
    y = df["service"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train RandomForestClassifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Predictions
    y_pred = model.predict(X_test)

    # ✅ Calculate accuracy
    accuracy = accuracy_score(y_test, y_pred)
    logging.info(f"Service Model Accuracy: {accuracy:.4f}")

    # ✅ Generate classification report
    report = classification_report(y_test, y_pred)
    logging.info("\nClassification Report:\n" + report)

    # ✅ Confusion Matrix Analysis
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(12, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=np.unique(y_test), yticklabels=np.unique(y_test))
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix for Service Prediction")
    plt.show()

    # ✅ Feature Importance Analysis
    feature_importances = pd.DataFrame({"Feature": X.columns, "Importance": model.feature_importances_})
    feature_importances = feature_importances.sort_values(by="Importance", ascending=False)

    plt.figure(figsize=(10, 5))
    sns.barplot(x=feature_importances["Importance"], y=feature_importances["Feature"])
    plt.xlabel("Feature Importance Score")
    plt.ylabel("Features")
    plt.title("Important Features for Service Prediction")
    plt.show()

    # Save the model
    joblib.dump(model, MODEL_SAVE_PATH)
    logging.info(f"Service model saved to {MODEL_SAVE_PATH}")

    return accuracy, report

def main():
    df = load_data(TRAIN_DATA_PATH)
    accuracy, report = train_service_model(df)
    logging.info(f"Final Model Accuracy: {accuracy:.4f}")
    logging.info(f"\n{report}")

if __name__ == "__main__":
    main()

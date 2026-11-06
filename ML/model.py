import pandas as pd
import json
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "techaastra_message_dataset.csv"

# 1. Load dataset (handles both true CSV and Excel format with .csv extension)
try:
    df = pd.read_csv(DATASET_PATH)
except Exception:
    df = pd.read_excel(DATASET_PATH)

# 2. Clean dataset
df = df.dropna(subset=["text", "label"])
df = df.drop_duplicates(subset=["text"])

X = df["text"].astype(str)
y = df["label"].astype(str)

# 3. Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# 4. Create ML pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=(1, 2),
        sublinear_tf=True
    )),

    ("classifier", LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=42
    ))
])

# 5. Train model
model.fit(X_train, y_train)

# 6. Test model
y_pred = model.predict(X_test)

print("\nMODEL EVALUATION")
print("----------------")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(
    y_test, y_pred,
    pos_label="phishing_or_scam",
    zero_division=0
))
print("Recall:", recall_score(
    y_test, y_pred,
    pos_label="phishing_or_scam",
    zero_division=0
))
print("F1 Score:", f1_score(
    y_test, y_pred,
    pos_label="phishing_or_scam",
    zero_division=0
))

print("\nClassification Report:")
print(classification_report(
    y_test, y_pred, zero_division=0
))

labels = sorted(y.unique())

print("Confusion Matrix:")
print(confusion_matrix(
    y_test, y_pred, labels=labels
))
print("Label order:", labels)

# 7. Train final model on all available data
final_model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=(1, 2),
        sublinear_tf=True
    )),

    ("classifier", LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=42
    ))
])

final_model.fit(X, y)

# 8. Save model
output_dir = BASE_DIR / "model_artifacts"
output_dir.mkdir(parents=True, exist_ok=True)

joblib.dump(
    final_model,
    output_dir / "techaastra_phishing_model.joblib"
)

print(f"\nModel saved successfully to {output_dir / 'techaastra_phishing_model.joblib'}!")

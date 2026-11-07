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

# Augment dataset with explicit scam, extortion, and cyber-threat patterns
SCAM_AUGMENTATION = [
    # Explicit Scam and Threats
    ("I will scam you", "phishing_or_scam", "scam", "synthetic"),
    ("i will scam you", "phishing_or_scam", "scam", "synthetic"),
    ("Iwill scam you and take your money", "phishing_or_scam", "scam", "synthetic"),
    ("I am a scammer and I will scam your account", "phishing_or_scam", "scam", "synthetic"),
    ("You have been scammed. Pay a recovery fee to get your money back", "phishing_or_scam", "scam", "synthetic"),
    ("This is a scam: send 500 dollars or your details will be published", "phishing_or_scam", "scam", "synthetic"),
    ("I have hacked your computer and recorded your webcam, pay ransom now", "phishing_or_scam", "extortion", "synthetic"),
    ("Blackmail notice: pay 500 in Bitcoin or your personal data will be leaked", "phishing_or_scam", "extortion", "synthetic"),
    ("You are being scammed. Transfer all remaining funds to this safe account", "phishing_or_scam", "scam", "synthetic"),
    ("Job opportunity: pay 500 deposit fee to start working from home scam", "phishing_or_scam", "scam", "synthetic"),
    ("Crypto investment scam: guaranteed 10x returns in 24 hours send Ethereum", "phishing_or_scam", "scam", "synthetic"),
    ("Immediate payment required: wire funds or face legal arrest scam", "phishing_or_scam", "scam", "synthetic"),
    ("Scammer demand: send Amazon gift card codes right now to cancel fine", "phishing_or_scam", "scam", "synthetic"),
    ("Extortion warning: send crypto to my wallet within 48 hours or face public release", "phishing_or_scam", "extortion", "synthetic"),
    ("I hacked into your system, send funds or your files will be deleted", "phishing_or_scam", "extortion", "synthetic"),
    ("Your phone has been compromised, pay ransom to decrypt your files", "phishing_or_scam", "extortion", "synthetic"),
    ("Scam alert: claim your free 1000 prize by submitting your banking password", "phishing_or_scam", "scam", "synthetic"),
    ("Fake refund: provide your UPI PIN to claim 5000 cashback", "phishing_or_scam", "scam", "synthetic"),
    # Legitimate counter-balancing samples
    ("We discussed common scam tactics in our cybersecurity class today", "legitimate", "academic", "synthetic"),
    ("Please report any suspicious scam emails to the university IT desk", "legitimate", "academic", "synthetic"),
    ("The lecture on fraud detection algorithms is scheduled for Monday", "legitimate", "academic", "synthetic"),
    ("Can you share the notes on how phishing filters work?", "legitimate", "academic", "synthetic"),
    ("Our team project presentation on scam prevention is due next Friday", "legitimate", "academic", "synthetic"),
    ("I received a weird message, could you check if it is safe?", "legitimate", "chat", "synthetic"),
    ("Let's meet at the library to finish our machine learning assignment", "legitimate", "chat", "synthetic"),
    ("Don't forget to submit your lab report before midnight", "legitimate", "academic", "synthetic"),
]

aug_df = pd.DataFrame(SCAM_AUGMENTATION, columns=["text", "label", "category", "source"])
df = pd.concat([df, aug_df], ignore_index=True)

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

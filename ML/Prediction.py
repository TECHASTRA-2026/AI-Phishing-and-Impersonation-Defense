import joblib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model_artifacts" / "techaastra_phishing_model.joblib"

_cached_model = None

def get_model():
    """Load and cache the trained ML model pipeline."""
    global _cached_model
    if _cached_model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model artifact not found at {MODEL_PATH}. "
                "Please run ML/model.py to train and save the model first."
            )
        _cached_model = joblib.load(MODEL_PATH)
    return _cached_model

def predict_message(message: str) -> dict:
    """
    Predict whether a message is phishing_or_scam or legitimate.
    Returns structured prediction, confidence, and class probabilities.
    """
    cleaned = (message or "").strip()
    if not cleaned:
        return {
            "prediction": "unknown",
            "is_phishing": False,
            "confidence": 0.0,
            "phishing_probability": 0.0,
            "probabilities": {}
        }

    model = get_model()
    prediction = model.predict([cleaned])[0]
    probabilities = model.predict_proba([cleaned])[0]
    classes = list(model.named_steps["classifier"].classes_)
    
    prob_dict = {
        cls_name: float(prob)
        for cls_name, prob in zip(classes, probabilities)
    }
    
    phishing_prob = prob_dict.get("phishing_or_scam", 0.0)
    confidence = max(probabilities)
    
    return {
        "prediction": prediction,
        "is_phishing": prediction == "phishing_or_scam",
        "confidence": round(float(confidence), 4),
        "phishing_probability": round(float(phishing_prob), 4),
        "probabilities": {k: round(v, 4) for k, v in prob_dict.items()}
    }

if __name__ == "__main__":
    message = input("Enter a message to analyze: ").strip()

    if not message:
        print("Please enter a message.")
    else:
        res = predict_message(message)
        print("\nPrediction:", res["prediction"])
        print("\nModel probability estimates:")
        for label, prob in res["probabilities"].items():
            print(f"{label}: {prob:.2%}")

        print(
            "\nNote: This is a baseline classifier, "
            "not a definitive security verdict."
        )

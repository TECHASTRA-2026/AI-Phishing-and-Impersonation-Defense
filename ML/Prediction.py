import joblib
from pathlib import Path

model_path = Path(
    "model_artifacts/techaastra_phishing_model.joblib"
)

model = joblib.load(model_path)

message = input("Enter a message to analyze: ").strip()

if not message:
    print("Please enter a message.")
else:
    prediction = model.predict([message])[0]

    probabilities = model.predict_proba([message])[0]
    classes = model.named_steps["classifier"].classes_

    print("\nPrediction:", prediction)

    print("\nModel probability estimates:")
    for label, probability in zip(classes, probabilities):
        print(f"{label}: {probability:.2%}")

    print(
        "\nNote: This is a baseline classifier, "
        "not a definitive security verdict."
    )
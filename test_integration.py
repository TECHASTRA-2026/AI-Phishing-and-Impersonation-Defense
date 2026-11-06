import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "API-Int"))
sys.path.insert(0, str(BASE_DIR / "security-layer"))
sys.path.insert(0, str(BASE_DIR / "ML"))

from integrations.message_service import analyze_message
from integrations.url_service import analyze_url
from services.risk_engine import calculate_risk

print("--- Testing analyze_message ---")
msg = "URGENT: Your SBI account has been locked. Verify immediately at http://sbi-verify.xyz"
msg_res = analyze_message(msg)
print("Classification:", msg_res["classification"])
print("Risk Score:", msg_res["risk_score"])
print("Indicators detected:", len(msg_res["indicators"]))
print("Impersonation findings:", len(msg_res["impersonation_findings"]))

print("\n--- Testing analyze_url ---")
url = "http://paypal-security-update.top/login"
url_res = analyze_url(url)
print("URL Status:", url_res["url_status"])
print("Risk Score:", url_res["risk_score"])
print("Level:", url_res["level"])

print("\n--- Testing calculate_risk ---")
combined_risk = calculate_risk(message_result=msg_res, url_result=url_res)
print("Final Risk Score:", combined_risk["risk_score"])
print("Final Risk Level:", combined_risk["risk_level"])
print("Summary:", combined_risk["summary"])
print("Items count:", len(combined_risk["items"]))
for item in combined_risk["items"][:3]:
    print(f"  * [{item['severity'].upper()}] {item['title']}: {item['summary']}")

print("\n--- Testing Legitimate Case ---")
good_msg = "Hey Hariom, don't forget the assignment submission today before 5pm."
good_url = "https://www.google.com"
good_res = calculate_risk(
    message_result=analyze_message(good_msg),
    url_result=analyze_url(good_url)
)
print("Legitimate Risk Score:", good_res["risk_score"])
print("Legitimate Risk Level:", good_res["risk_level"])
print("Summary:", good_res["summary"])

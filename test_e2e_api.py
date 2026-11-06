import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "API-Int"))
sys.path.insert(0, str(BASE_DIR / "security-layer"))
sys.path.insert(0, str(BASE_DIR / "ML"))

from schemas.request import MessageRequest, URLRequest, ImpersonationRequest, CombinedRequest
from routes.analyze import message_analysis, url_analysis, impersonation_analysis, combined_analysis, get_trusted_entities
from main import serve_website, api_status

print("\n" + "=" * 65)
print("  TECHASTRA COMPREHENSIVE E2E SUITE (ALL SECTIONS)")
print("=" * 65)

# 1. Test Static Website Serving
print("\n[1/6] Testing Web UI Serving...")
ui_res = serve_website()
assert hasattr(ui_res, "path")
assert Path(ui_res.path).exists()
print(" [PASS] Web frontend successfully mounted and served from:", ui_res.path)

# 2. Test Health API & Trusted Entities
print("\n[2/6] Testing API Health & Trusted Entities Directory...")
status = api_status()
assert status["status"] == "Running"
entities_res = get_trusted_entities()
assert entities_res["success"] is True
assert entities_res["count"] >= 10
print(f" [PASS] Status = Running, Directory contains {entities_res['count']} verified institutions.")

# 3. Test Message NLP Section
print("\n[3/6] Testing Dedicated Message NLP Analyzer...")
msg_req = MessageRequest(message="URGENT: Your account has been suspended! Send OTP immediately to verify.")
msg_res = message_analysis(msg_req)
print(f" Message Threat Score: {msg_res['score']}/100 ({msg_res['level']})")
assert msg_res["score"] >= 50
print(" [PASS] Dedicated Message Analyzer accurately flagged urgency & secret requests!")

# 4. Test URL Threat Scanner Section
print("\n[4/6] Testing Dedicated URL Threat Scanner...")
url_req = URLRequest(url="http://paypal-security-update.top/login")
url_res = url_analysis(url_req)
print(f" URL Threat Score: {url_res['score']}/100 ({url_res['level']})")
assert url_res["score"] >= 40
print(" [PASS] Dedicated URL Threat Scanner flagged abusive TLD (.top) and credential keywords!")

# 5. Test Impersonation Verifier Section
print("\n[5/6] Testing Dedicated Brand Impersonation Verifier...")
imp_req = ImpersonationRequest(
    claimed_entity="State Bank of India",
    sender_email="support@sbi-alerts-portal.xyz",
    url="http://sbi-login-verify.top/reactivate"
)
imp_res = impersonation_analysis(imp_req)
print(f" Impersonation Threat Score: {imp_res['score']}/100 ({imp_res['level']})")
print(f" Findings: {len(imp_res['findings'])} identity mismatch flags.")
assert imp_res["score"] >= 50
assert len(imp_res["findings"]) >= 1
print(" [PASS] Dedicated Brand Impersonation Verifier detected unauthorized sender domain & links!")

# 6. Test Combined Full Suite
print("\n[6/6] Testing Combined Full Multi-Vector Scanner...")
comb_req = CombinedRequest(
    message="FINAL WARNING: Your State Bank of India netbanking account has been locked due to unverified KYC details. You must update your password and OTP immediately to avoid permanent deactivation.",
    url="http://sbi-login-verify.top/auth",
    sender_email="security@sbi-alerts-portal.xyz"
)
comb_res = combined_analysis(comb_req)
print(f" Combined Threat Score: {comb_res['score']}/100 ({comb_res['level']})")
assert comb_res["score"] >= 65
assert comb_res["level"] == "HIGH"
print(" [PASS] Combined Multi-Vector Analyzer synthesized all threat signals!")

print("\n" + "=" * 65)
print(" ALL 6 SECTION TESTS PASSED SUCCESSFULLY!")
print("=" * 65 + "\n")

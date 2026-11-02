from security_layer import analyze_message, analyze_url

CASES = [
 ("CASE 01 Legitimate", dict(
   text="Hi Anuj, your HDFC Bank monthly statement is ready. View it at https://www.hdfcbank.com/personal/statements",
   sender_email="alerts@hdfcbank.com", sender_name="HDFC Bank"), {"Low"}),
 ("CASE 02 Suspicious", dict(
   text="URGENT: your account will be suspended within 24 hours. Reply with your OTP and password to avoid penalty.",
   sender_email="help@random-mail.com"), {"High", "Critical"}),
 ("CASE 03 Identity mismatch", dict(
   text="This is Microsoft support. Sign in at https://microsoft-support.account-check.xyz to keep your Office 365 active.",
   sender_email="support@micros0ft-helpdesk.com", sender_name="Microsoft Support"), {"High", "Critical"}),
 ("CASE 04 URL warning", dict(
   text="Here is the document you asked for: http://192.168.4.77/secure/login@paypa1.com/verify?id=88",
   sender_email="friend@gmail.com"), {"Medium", "High", "Critical"}),
 ("CASE 05 Lookalike link only", dict(
   text="Your Amazon order has shipped. Track: https://amaz0n.in/track", sender_email="ship@amaz0n.in", sender_name="Amazon"), {"High", "Critical"}),
 ("CASE 06 Normal chat", dict(text="Hey, are we meeting at 5 pm for the project discussion?", sender_email="a@gmail.com"), {"Low"}),
]

if __name__ == "__main__":
    ok = True
    for name, kw, expected in CASES:
        r = analyze_message(**kw)
        passed = r["level"] in expected
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'}  {name:28s} score={r['score']:3d} level={r['level']:8s} {r['breakdown']}")
    for u in ["https://www.paypal.com/signin", "https://paypal-secure-login.verify-account.example.top/a"]:
        print("URL ", u, "->", analyze_url(u)["score"], [s["code"] for s in analyze_url(u)["signals"]])
    raise SystemExit(0 if ok else 1)

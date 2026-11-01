"""Generate the demo dataset:  python -m scripts.generate_sample_data

The data is SYNTHETIC (template-based) so the repo runs out of the box.
For real-world accuracy, retrain on a public dataset (see README).
"""
import csv
import random
from pathlib import Path

random.seed(42)

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "PNB", "Bank of Baroda"]
BRANDS = ["PayPal", "Amazon", "Netflix", "Microsoft", "Apple", "Paytm", "PhonePe", "Google", "Flipkart", "Instagram"]
BAD_URLS = [
    "http://sbi-kyc-update.xyz/login", "bit.ly/3xKyc9", "http://192.168.4.21/verify",
    "https://secure-paypal-login.top/account", "http://amazon-reward.click/claim",
    "https://hdfc-netbanking.verify-now.tk/", "tinyurl.com/upd8-kyc",
    "http://paytm.support-help.work/refund", "https://netflix-billing-update.site/pay",
    "http://microsoft-security-alert.online/unlock", "http://xn--pypal-4ve.com/login",
]
GOOD_URLS = ["https://www.amazon.in/orders", "https://www.hdfcbank.com", "https://www.irctc.co.in", "https://www.netflix.com/account"]

PHISH = [
    "Dear customer, your {bank} account will be suspended within {hours} hours. Complete KYC immediately: {bad}",
    "URGENT: Unauthorized login detected on your {brand} account. Verify your password now at {bad}",
    "Congratulations! You have won Rs {amount} in the {brand} lucky draw. Claim your prize now: {bad}",
    "Your {bank} debit card is blocked. Share your card number, CVV and OTP to reactivate it.",
    "Final notice: your {brand} subscription payment failed. Update your billing details within {hours} hours to avoid termination {bad}",
    "Income tax refund of Rs {amount} is pending. Verify your PAN and Aadhaar at {bad} to receive it.",
    "Work from home and earn Rs {amount} per day. No experience needed. Pay a small registration fee to start. WhatsApp us now.",
    "This is Microsoft Support. Your computer is infected. Call immediately or buy gift cards to remove the virus.",
    "You have a payment request of Rs {amount} on UPI. Enter your UPI PIN to accept: {bad}",
    "Your parcel is held at customs. Pay a processing fee of Rs {amount} within {hours} hours: {bad}",
    "Security alert from {brand}: your account has been locked. Confirm your identity and send your password to unlock: {bad}",
    "Dear user, your electricity will be disconnected tonight. Pay the pending bill immediately via {bad} or call our officer.",
    "I am a prince and need your help to transfer ${amount} million. Send your bank details and I will share 30 percent with you.",
    "{bank} ALERT!! Unusual activity on your account. Click here to verify: {bad}",
    "Your {brand} account has been suspended. Re-KYC is mandatory, update your details now {bad}",
    "Exclusive offer! Guaranteed returns of 40 percent in 7 days. Invest in crypto today, limited slots, act now.",
]
LEGIT = [
    "Hi team, the sprint review is scheduled for tomorrow at {time}. Please update your tickets before the meeting.",
    "Your OTP for {brand} login is {otp}. It is valid for 10 minutes. Do not share this OTP with anyone.",
    "Your order #{order} has been shipped and will arrive by Friday. Track it in the {brand} app.",
    "Thanks for your payment of Rs {amount} to {brand}. Your receipt is attached.",
    "Reminder: your dentist appointment is on Monday at {time}. Reply YES to confirm.",
    "Hey, are we still meeting for lunch today? I am free after 1 pm.",
    "Your {bank} statement for October is now available in net banking. Log in through the official app to view it: {good}",
    "Happy birthday! Wishing you a wonderful year ahead. Let us catch up this weekend.",
    "Assignment 3 deadline has been extended to Friday. Submit it on the college portal.",
    "Your monthly newsletter: five tips to improve your Python skills, plus new tutorials this week.",
    "Rs {amount} debited from A/c XX{acct} for UPI payment to Swiggy. If this was not you, call the official helpline printed on your card.",
    "Interview scheduled for {time} on Monday. Please bring a copy of your resume and ID.",
    "Can you send me the notes from yesterday's class? I missed the second half.",
    "Your {brand} subscription renews on the 15th. Manage your plan any time in the app settings.",
    "The library book you reserved is ready for pickup until Saturday. See you there. {good}",
    "Meeting notes from today are in the shared drive. Let me know if I missed anything.",
]


def fill(tpl: str) -> str:
    return tpl.format(
        bank=random.choice(BANKS), brand=random.choice(BRANDS),
        bad=random.choice(BAD_URLS), good=random.choice(GOOD_URLS),
        amount=random.choice([499, 1500, 2500, 9800, 25000, 50000, 5]),
        hours=random.choice([2, 4, 12, 24, 48]),
        time=random.choice(["10 am", "11:30 am", "2 pm", "4:15 pm"]),
        otp=random.randint(100000, 999999), order=random.randint(10000, 99999),
        acct=random.randint(1000, 9999),
    )


rows = set()
for label, templates, per in ((1, PHISH, 10), (0, LEGIT, 10)):
    for tpl in templates:
        for _ in range(per):
            rows.add((fill(tpl), label))

out = Path(__file__).resolve().parent.parent / "data" / "sample_dataset.csv"
out.parent.mkdir(exist_ok=True)
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["text", "label"])
    w.writerows(sorted(rows))
print(f"Wrote {len(rows)} rows to {out}")

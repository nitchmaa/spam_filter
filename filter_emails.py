from fetch_emails import authenticate_gmail, get_email_body  # Import functions from fetch_emails.py
import os
import pickle
import base64
import email
from googleapiclient.discovery import build

SPAM_KEYWORDS = ["lottery", "win", "congratulations", "urgent", "click here", "unsubscribe"]

def is_spam(email_body):
    """Basic keyword-based spam detection."""
    for keyword in SPAM_KEYWORDS:
        if keyword.lower() in email_body.lower():
            return True
    return False

def fetch_and_filter_emails():
    creds = authenticate_gmail()  # Now it will use the imported function
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(userId="me", maxResults=5).execute()
    messages = results.get("messages", [])

    if not messages:
        print("No new emails found.")
        return

    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        headers = msg_data["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
        body = get_email_body(msg_data["payload"])  # Using the imported function

        category = "SPAM" if is_spam(body) else "IMPORTANT"

        print(f"[{category}] From: {sender}")
        print(f"Subject: {subject}")
        print("=" * 50)

if __name__ == "__main__":
    fetch_and_filter_emails()

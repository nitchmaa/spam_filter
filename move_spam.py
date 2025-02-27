import os
import pickle
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# UPDATED SCOPES TO ALLOW MODIFYING EMAILS
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

SPAM_KEYWORDS = ["lottery", "win", "congratulations", "urgent", "click here", "unsubscribe"]

def authenticate_gmail():
    """Authenticates with Gmail API and handles token storage."""
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
        creds = flow.run_local_server(port=0)

        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    return creds

def get_email_body(payload):
    """Extracts the plain text body of an email."""
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                return base64.urlsafe_b64decode(part["body"]["data"]).decode()
    elif "body" in payload and "data" in payload["body"]:
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode()
    return "No body content."

def is_spam(email_body):
    """Detects spam using simple keyword filtering."""
    for keyword in SPAM_KEYWORDS:
        if keyword.lower() in email_body.lower():
            return True
    return False

def move_to_spam(service, email_id):
    """Moves an email to the spam folder by modifying its labels."""
    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={"removeLabelIds": ["INBOX"], "addLabelIds": ["SPAM"]}
    ).execute()
    print(f"✅ Moved email {email_id} to Spam.")

def fetch_and_filter_emails():
    """Fetches emails, detects spam, and moves spam emails to the Spam folder."""
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(userId="me", maxResults=5).execute()
    messages = results.get("messages", [])

    if not messages:
        print("📭 No new emails found.")
        return

    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        headers = msg_data["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
        body = get_email_body(msg_data["payload"])

        if is_spam(body):
            print(f"🛑 [SPAM] Moving email from {sender} to Spam...")
            move_to_spam(service, msg["id"])
        else:
            print(f"✅ [IMPORTANT] From: {sender} | Subject: {subject}")

if __name__ == "__main__":
    fetch_and_filter_emails()

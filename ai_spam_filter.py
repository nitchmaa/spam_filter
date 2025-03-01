import os
import pickle
import base64
import email
import time
import re
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import joblib
import numpy as np

# Gmail API scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Load spam classifier
SPAM_CLASSIFIER_MODEL = "spam_classifier.pkl"
if not os.path.exists(SPAM_CLASSIFIER_MODEL):
    raise FileNotFoundError("Spam classifier model not found!")
model = joblib.load(SPAM_CLASSIFIER_MODEL)

# Authenticate Gmail without opening a browser
def authenticate_gmail():
    creds = None
    token_path = "token.pickle"
    credentials_path = "credentials.json"

    # Load existing credentials
    if os.path.exists(token_path):
        with open(token_path, "rb") as token:
            creds = pickle.load(token)

    # Refresh credentials if expired
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_console()  # Use console-based authentication

        # Save new credentials
        with open(token_path, "wb") as token:
            pickle.dump(creds, token)

    return creds

# Connect to Gmail API
def get_gmail_service():
    creds = authenticate_gmail()
    return build("gmail", "v1", credentials=creds)

# Fetch unread emails
def fetch_unread_emails():
    service = get_gmail_service()
    results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
    messages = results.get("messages", [])
    return messages

# Extract email content
def get_email_content(service, msg_id):
    msg = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    msg_bytes = base64.urlsafe_b64decode(msg["raw"])
    msg_email = email.message_from_bytes(msg_bytes)

    subject = msg_email["Subject"] or "No Subject"
    sender = msg_email["From"] or "Unknown Sender"
    body = ""

    # Get the body text
    if msg_email.is_multipart():
        for part in msg_email.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body = msg_email.get_payload(decode=True).decode(errors="ignore")

    return sender, subject, body

# Classify email as spam or not spam
def is_spam(text):
    text_cleaned = re.sub(r"\W+", " ", text.lower())  # Remove special characters
    vectorized_text = np.array([text_cleaned])  # Convert text into numpy array for model
    return model.predict(vectorized_text)[0] == "spam"

# Move email to spam
def move_email_to_spam(service, msg_id):
    service.users().messages().modify(userId="me", id=msg_id, body={"addLabelIds": ["SPAM"]}).execute()

# Process unread emails
def fetch_and_filter_emails():
    service = get_gmail_service()
    messages = fetch_unread_emails()

    if not messages:
        print("No new emails found.")
        return

    for msg in messages:
        msg_id = msg["id"]
        sender, subject, body = get_email_content(service, msg_id)

        if is_spam(body):
            print(f"Moving email from {sender} ({subject}) to Spam.")
            move_email_to_spam(service, msg_id)
        else:
            print(f"Email from {sender} ({subject}) is safe.")

# Run the email filtering process
if __name__ == "__main__":
    fetch_and_filter_emails()

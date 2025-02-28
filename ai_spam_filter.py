import os
import pickle
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Load trained AI model
with open("/workspace/spam_filter/spam_classifier.pkl", "rb") as f:
    model = pickle.load(f)

# Gmail API scope for modifying emails
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# List of senders to automatically mark as spam (except password reset emails)
UNWANTED_SENDERS = [
    "no-reply@linkedin.com",
    "alerts@linkedin.com",
    "jobs@indeed.com",
    "noreply@glassdoor.com",
    "updates@monster.com",
    "notifications@careerbuilder.com",
    "marketing@somejobboard.com"
]

# Keywords that indicate a **password reset** email
PASSWORD_RESET_KEYWORDS = [
    "password reset",
    "reset your password",
    "account recovery",
    "change your password",
    "reset link",
    "forgot your password",
    "recover your account"
]

# Load whitelist and blacklist
WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"

def load_override_list(file_path):
    """Loads a list of email addresses or keywords from a text file."""
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return [line.strip().lower() for line in f.readlines()]
    return []

whitelist = load_override_list(WHITELIST_FILE)
blacklist = load_override_list(BLACKLIST_FILE)

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
                return base64.urlsafe_b64decode(part["body"]["data"]).decode(errors="ignore")
    elif "body" in payload and "data" in payload["body"]:
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode(errors="ignore")
    return "No body content."

def contains_password_reset(body):
    """Checks if an email contains password reset-related keywords."""
    body_lower = body.lower()
    return any(keyword in body_lower for keyword in PASSWORD_RESET_KEYWORDS)

def is_spam_ai(email_body):
    """Uses trained AI model to predict if an email is spam."""
    return model.predict([email_body])[0] == 1  # Returns True if spam, False if not

def move_to_spam(service, email_id):
    """Moves an email to the spam folder."""
    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={"removeLabelIds": ["INBOX"], "addLabelIds": ["SPAM"]}
    ).execute()
    print(f"✅ Moved email {email_id} to Spam.")

def fetch_and_filter_emails():
    """Fetches emails, uses AI for spam detection, and moves spam to the Spam folder."""
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", [])

    if not messages:
        print("📭 No new emails found.")
        return

    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        headers = msg_data["payload"]["headers"]
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender").lower()
        body = get_email_body(msg_data["payload"])

        # Rule 1: If sender is in the whitelist, keep in Inbox
        if sender in whitelist:
            print(f"🔓 [WHITELISTED] Email from {sender}. Keeping in Inbox.")
            continue

        # Rule 2: If sender is in the blocked list but the email is a password reset, allow it.
        if any(unwanted in sender for unwanted in UNWANTED_SENDERS):
            if contains_password_reset(body):
                print(f"🔓 [ALLOWED] Password reset email from {sender}. Keeping in Inbox.")
                continue  # Skip moving to spam

            print(f"🛑 [AUTO-SPAM] Unwanted sender {sender}. Moving to Spam...")
            move_to_spam(service, msg["id"])
            continue

        # Rule 3: If sender is in the blacklist, force move to Spam
        if sender in blacklist or any(keyword in subject.lower() for keyword in blacklist):
            print(f"🛑 [FORCED SPAM] Blacklisted sender {sender}. Moving to Spam...")
            move_to_spam(service, msg["id"])
            continue

        # Rule 4: Use AI to classify the email
        if is_spam_ai(body):
            print(f"🛑 [SPAM] AI detected spam from {sender}. Moving to Spam...")
            move_to_spam(service, msg["id"])
        else:
            print(f"✅ [IMPORTANT] AI detected as safe. From: {sender} | Subject: {subject}")

if __name__ == "__main__":
    fetch_and_filter_emails()

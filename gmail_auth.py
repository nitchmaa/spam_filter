import os
import pickle
import base64
import email
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying these SCOPES, delete the token.pickle file.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def authenticate_gmail():
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    return creds

def fetch_emails():
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    # Get the latest 10 emails
    results = service.users().messages().list(userId="me", maxResults=10).execute()
    messages = results.get("messages", [])

    if not messages:
        print("No new emails found.")
        return

    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        snippet = msg_data["snippet"]
        print(f"Email Snippet: {snippet}\n")

if __name__ == "__main__":
    fetch_emails()

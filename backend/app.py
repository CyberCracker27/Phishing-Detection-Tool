from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import base64
import json
import email
import numpy as np
import pickle
import pandas as pd
from feature import FeatureExtraction
from email_content_analyzer import EmailContentAnalyzer  # Import the EmailContentAnalyzer class

app = Flask(__name__)
CORS(app)

# Gmail API setup
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'credentials.json'  # Your downloaded OAuth credentials
REDIRECT_URI = 'http://127.0.0.1:5000/oauth2callback'
credentials = None  # Global in-memory credentials
flow = None  # Global OAuth flow object
auth_state = "pending"  # Track authentication status

# Load client secret from credentials.json
with open(CREDENTIALS_FILE, 'r') as f:
    creds_data = json.load(f)
    CLIENT_ID = creds_data['web']['client_id']
    CLIENT_SECRET = creds_data['web']['client_secret']

try:
    file = open("model.pkl", "rb")
    gbc = pickle.load(file)
except Exception as e:
    print(f"Error loading phishing detection model: {e}")
    gbc = None

# Initialize the EmailContentAnalyzer with the pre-trained model
content_analyzer = EmailContentAnalyzer(model_path="phishing_model.pkl")

def get_gmail_service():
    global credentials
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            print("Credentials refreshed in memory.")
        else:
            return None  # Not authenticated yet
    return build('gmail', 'v1', credentials=credentials)

@app.route('/start_auth', methods=['POST'])
def start_auth():
    global flow, auth_state
    auth_state = "pending"
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    print(f"Using client_id: {CLIENT_ID} and client_secret: {CLIENT_SECRET[:4]}**** for OAuth flow")
    return jsonify({"auth_url": auth_url})

@app.route('/oauth2callback')
def oauth2callback():
    global credentials, flow, auth_state
    if not flow:
        return "Error: OAuth flow not initialized", 400
    try:
        # Exchange authorization code for tokens using client_secret
        flow.fetch_token(code=request.args.get('code'))
        credentials = flow.credentials
        auth_state = "authenticated"
        print("Credentials obtained and stored in memory for this session.")
        print(f"Access Token: {credentials.token[:10]}... (truncated)")
        print(f"Refresh Token: {credentials.refresh_token[:10]}... (truncated)")
        return "Authentication successful! You can close this tab and return to the extension."
    except Exception as e:
        auth_state = "failed"
        print(f"Callback error: {e}")
        return f"Authentication failed: {str(e)}", 500

@app.route('/auth_status')
def auth_status():
    global credentials, auth_state
    if auth_state != "authenticated" or not credentials or not credentials.valid:
        return jsonify({"status": auth_state, "user": None})

    try:
        # Fetch the authenticated user's email address
        service = get_gmail_service()
        if not service:
            return jsonify({"status": "error", "user": None})

        profile = service.users().getProfile(userId='me').execute()
        authenticated_user = profile.get('emailAddress', 'Unknown')
        return jsonify({"status": auth_state, "user": authenticated_user})
    except Exception as e:
        print(f"Error fetching authenticated user: {e}")
        return jsonify({"status": "error","user": None})

def load_phishing_links():
    try:
        with open("phishing_links.txt", "r") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        print("Error: phishing_links.txt not found.")
        return set()

phishing_links = load_phishing_links()

@app.route('/check_email', methods=['POST'])
def check_email():
    total_phishing_prob = 0
    total_non_phishing_prob = 0
    phis_pro = 0
    non_phis_pro = 0
    global credentials

    # Check if the user is authenticated
    if not credentials or not credentials.valid:
        return jsonify({"error": "Not authenticated. Please authenticate first."}), 401

    # Parse the request data
    data = request.get_json()
    links = data.get("links", [])
    message_id = data.get("message_id", "")

    if not message_id:
        return jsonify({"error": "No message_id provided"}), 400

    # 1. Check against known phishing links
    is_link = any(link in phishing_links for link in links)

    # 3. Analyze email content using EmailContentAnalyzer (do this before URL analysis for weighted average)
    email_body = ""
    content_analysis_result = {}
    try:
        service = get_gmail_service()
        if not service:
            return jsonify({"error": "Authentication required"}), 401

        message = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        raw_email = base64.urlsafe_b64decode(message['raw']).decode('utf-8')
        parsed_email = email.message_from_string(raw_email)

        # Extract email body
        print("\n=== Email Body ===")
        if parsed_email.is_multipart():
            for part in parsed_email.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Skip attachments
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    email_body = part.get_payload(decode=True).decode('utf-8')
                    print(email_body)
                    break
        else:
            email_body = parsed_email.get_payload(decode=True).decode('utf-8')
            print(email_body)

        # Analyze email content
        headers = {header: value for header, value in parsed_email.items()}
        try:
            content_analysis_result = content_analyzer.predict(email_body, headers)
        except Exception as ex:
            import traceback
            print(f"Exception during content analysis prediction: {ex}")
            traceback.print_exc()
            content_analysis_result = {}

    except Exception as e:
        print(f"Error analyzing email content: {e}")
        email_body = "Failed to fetch email content"

    # 2. Analyze URLs with ML model
    is_model = False
    url_analysis_results = []
    if gbc:
        try:
            for url in links:
                obj = FeatureExtraction(url)
                features = obj.getFeaturesList()
                # Use the feature names from the trained model
                feature_names = list(gbc.feature_names_in_)
                x_df = pd.DataFrame([features], columns=feature_names)

                # Make prediction
                y_pro_phishing = gbc.predict_proba(x_df)[0, 1]
                y_pro_non_phishing = gbc.predict_proba(x_df)[0, 0]

                # Update total probabilities
                total_phishing_prob += y_pro_phishing
                total_non_phishing_prob += y_pro_non_phishing

                # Check if the URL is classified as phishing
                is_phishing_url = bool(gbc.predict(x_df)[0] == 1)  # Assuming label 1 means phishing
                url_analysis_results.append({
                    "url": url,
                    "is_phishing": is_phishing_url,
                    "phishing_probability": round(y_pro_phishing * 100, 2),
                    "non_phishing_probability": round(y_pro_non_phishing * 100, 2)
                })

                if is_phishing_url:
                    is_model = True

            # Calculate average probabilities for URLs
            if links:
                average_phishing_prob = total_phishing_prob / len(links)
                average_non_phishing_prob = total_non_phishing_prob / len(links)
                phis_pro = round(average_phishing_prob * 100, 2)
                non_phis_pro = round(average_non_phishing_prob * 100, 2)
        except Exception as e:
            print(f"URL analysis error: {e}")

    # Combine content analysis phishing probability if available
    content_phishing_prob = content_analysis_result.get('phishing_probability', 0) * 100 if content_analysis_result else 0
    if content_phishing_prob > 0 and phis_pro > 0:
        # Weighted average: 70% content analysis, 30% URL analysis
        phis_pro = round(0.7 * content_phishing_prob + 0.3 * phis_pro, 2)
        non_phis_pro = round(100 - phis_pro, 2)
    elif content_phishing_prob > 0:
        phis_pro = round(content_phishing_prob, 2)
        non_phis_pro = round(100 - phis_pro, 2)

    # After calculating phis_pro and non_phis_pro
    if phis_pro == 0 and non_phis_pro == 0:
        # No prediction could be made
        phis_pro = 0
        non_phis_pro = 100

    # Final phishing determination
    is_phishing = bool(is_link or is_model or content_analysis_result.get('is_phishing', False))
    print(f"Is Link Phishing: {is_link}, Is Model Phishing: {is_model}, Is Content Phishing: {content_analysis_result.get('is_phishing', False)}")
    print(f"Message ID: {message_id}")
    print(f"Links: {links}")
    print(f"Is Phishing: {is_phishing}")

    # Ensure all fields are JSON-serializable
    content_analysis_result = {k: (v if isinstance(v, (str, int, float, bool, list, dict)) else str(v))
                               for k, v in content_analysis_result.items()}

    # Return the result
    return jsonify({
        "is_phishing": is_phishing,
        "phis_pro": phis_pro,
        "non_phis_pro": non_phis_pro,
        "url_analysis": url_analysis_results,
        "content_analysis": content_analysis_result,
        "email_body": email_body
    })

if __name__ == '__main__':
    app.run(debug=True)
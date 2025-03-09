from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import re  # For regex to extract domains from email content
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
# List of suspicious words that may indicate phishing
suspicious_words = ["free","urgent","limited time","act now","winner","money","cash prize","click here","unsecured","bank account","confirm","account suspended", "win", "exclusive offer", "risk-free", "urgent action", 
    "guaranteed","don't miss","limited offer","act fast","immediate response","verify your identity","account locked","security breach","password","social security number", "sensitive information", "bank details", "update account"
]
# Predefined list of MNC company official domains
valid_domains = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "tesla": "tesla.com"
}
# Additional aggressive checks
def check_for_urgent_tone(content):
    urgent_phrases = ["act fast","hurry","limited time","now","don't miss","immediate","last chance","expires soon"]
    return any(phrase in content for phrase in urgent_phrases)
def check_for_links(content):
    return "http" in content or "www" in content
def check_for_excessive_caps(content):
    return len([word for word in content.split() if word.isupper()]) > 5  # More than 5 words in caps
def check_for_sensitive_info(content):
    sensitive_info = ["password", "bank account", "social security", "credit card", "account number", "login credentials"]
    return any(phrase in content for phrase in sensitive_info)
def check_for_official_domain(email_content):
    # Regex to extract an email domain from the content
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_content)
    if match:
        domain = match.group(1)
        # Check if the domain is in the list of valid domains
        for company, valid_domain in valid_domains.items():
            if domain.lower() == valid_domain.lower():
                return True  # The email domain matches an official domain
    return False  # No match found

@app.route('/')
def index():
    return 'Welcome to the Email Safety Checker API'

@app.route('/check_email', methods=['POST'])
def check_email():
    email_content = request.json.get('email_content', '').lower()
    safety_score = 100   
    # Check for suspicious words in the email content
    suspicious_count = 0
    for word in suspicious_words:
        if word in email_content:
            suspicious_count += 1
            safety_score -= 25  # Increased penalty for each suspicious word found
    # Additional aggressive checks
    if check_for_urgent_tone(email_content):
        safety_score -= 30  # Major penalty for urgent language    
    if check_for_links(email_content):
        safety_score -= 40  # Major penalty for links, commonly used in phishing attempts    
    if check_for_excessive_caps(email_content):
        safety_score -= 50  # Huge penalty for excessive capitalization    
    if check_for_sensitive_info(email_content):
        safety_score -= 60  # Heavy penalty for requests involving sensitive info    
    # Check if the email domain matches official company domains
    if not check_for_official_domain(email_content):
        safety_score -= 20  # Deduct 20 points if domain doesn't match    
    # Increase the penalty based on how many suspicious words were found
    safety_score -= suspicious_count * 10
    # Ensure the score doesn't go below 0
    safety_score = max(safety_score, 0)
    # Prepare the response with more aggressive messaging
    if safety_score < 20:
        result_message = "Critical Danger: This email is almost certainly a phishing attempt! Do not engage!"
    elif safety_score < 40:
        result_message = "Extreme Warning: This email is highly suspicious and likely a phishing attempt. Proceed with caution!"
    elif safety_score < 60:
        result_message = "Warning: This email contains significant suspicious elements. It might be a phishing attempt."
    elif safety_score < 80:
        result_message = "Caution: Some elements of this email are suspicious. Be wary of links and requests for personal information."
    else:
        result_message = "This email appears safe, but always exercise caution and verify its source."
    return jsonify({
        'safety_score': safety_score,
        'result_message': result_message
    })
if __name__ == '__main__':
    app.run(debug=True)

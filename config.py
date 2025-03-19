"""
Configuration constants for Google Workspace Alerts Wodle.
"""
import logging

# Wodle identifier
WODLE_NAME = "google-workspace-alerts"

# Default paths and settings
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_SOCKET_PATH = "/var/ossec/queue/sockets/queue"
DEFAULT_LOG_FILE = "/var/ossec/logs/google_workspace_alerts_wodle.log"
DEFAULT_STATE_FILE = "/var/ossec/var/google_workspace_alerts_wodle_state.json"
DEFAULT_CONFIG_FILE = "/var/ossec/wodles/google_workspace_alerts/config.json"
MAX_STORED_ALERT_IDS = 10000

# OAuth constants
GOOGLE_API_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_API_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_API_AUTH_PROVIDER_X509_CERT_URL = "https://www.googleapis.com/oauth2/v1/certs"
GOOGLE_API_SCOPES = ["https://www.googleapis.com/auth/apps.alerts"]

# Alert types from Google Workspace
GOOGLE_ALERT_TYPES = [
    "Access Approvals request",
    "Account suspension warning",
    "Activity Rule",
    "APNS certificate has expired",
    "APNS certificate is expiring soon",
    "Calendar settings changed",
    "Chrome devices auto-update expiration warning",
    "Customer abuse detected",
    "Customer takeout initiated",
    "Data Loss Prevention",
    "Device compromised",
    "Drive settings changed",
    "Email settings changed",
    "Government attack warning",
    "Leaked password",
    "Malware reclassification",
    "Misconfigured whitelist",
    "Mobile settings changed",
    "New user Added",
    "Phishing reclassification",
    "Primary admin changed",
    "Reporting Rule",
    "SSO profile added",
    "SSO profile deleted",
    "SSO profile updated",
    "Super admin password reset",
    "Suspended user made active",
    "Suspicious activity",
    "Suspicious login",
    "Suspicious login (less secure app)",
    "Suspicious message reported",
    "Suspicious programmatic login",
    "User deleted",
    "User granted Admin privilege",
    "User reported phishing",
    "User reported spam spike",
    "User suspended",
    "User suspended (Administrator email alert)",
    "User suspended (spam)",
    "User suspended (spam through relay)",
    "User suspended (suspicious activity)",
    "Users Admin privilege revoked",
    "Users password changed"
]
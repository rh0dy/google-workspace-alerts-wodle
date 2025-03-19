"""
Google API authentication and service functions.
"""
import logging
from typing import Dict
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build, Resource

from config import (
    GOOGLE_API_AUTH_URI, GOOGLE_API_TOKEN_URI,
    GOOGLE_API_AUTH_PROVIDER_X509_CERT_URL, GOOGLE_API_SCOPES
)

def authenticate(google_api_config: Dict[str, str], logger: logging.Logger) -> Credentials:
    """
    Authenticate to Google API using service account credentials.

    Args:
        google_api_config: Dictionary containing Google API configuration
        logger: Logger instance for logging

    Returns:
        Delegated credentials for the Google API

    Raises:
        ValueError: If required configuration keys are missing
        Exception: If authentication fails
    """
    try:
        # Check for required configuration
        required_keys = ["project_id", "private_key_id", "private_key",
                        "client_email", "client_id", "client_x509_cert_url",
                        "delegated_account"]

        missing_keys = [key for key in required_keys if not google_api_config.get(key)]
        if missing_keys:
            error_msg = f"Missing required Google API configuration: {', '.join(missing_keys)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Create service account info dictionary
        google_api_service_account_info = {
            "type": "service_account",
            "project_id": google_api_config["project_id"],
            "private_key_id": google_api_config["private_key_id"],
            "private_key": google_api_config["private_key"].replace("\\n", "\n"),
            "client_email": google_api_config["client_email"],
            "client_id": google_api_config["client_id"],
            "auth_uri": GOOGLE_API_AUTH_URI,
            "token_uri": GOOGLE_API_TOKEN_URI,
            "auth_provider_x509_cert_url": GOOGLE_API_AUTH_PROVIDER_X509_CERT_URL,
            "client_x509_cert_url": google_api_config["client_x509_cert_url"]
        }

        # Create credentials and delegate
        logger.debug("Creating service account credentials")
        google_api_credentials = Credentials.from_service_account_info(
            google_api_service_account_info,
            scopes=GOOGLE_API_SCOPES
        )

        delegated_account = google_api_config["delegated_account"]
        logger.debug(f"Delegating credentials to {delegated_account}")
        google_api_credentials_delegated = google_api_credentials.with_subject(delegated_account)

        return google_api_credentials_delegated
    except Exception as e:
        logger.error(f"Google API authentication error: {str(e)}")
        raise

def get_alerts_service(credentials: Credentials, logger: logging.Logger) -> Resource:
    """
    Get the Google Alert Center API service.

    Args:
        credentials: Authenticated Google credentials
        logger: Logger instance for logging

    Returns:
        Google API service resource for Alert Center

    Raises:
        Exception: If building the service fails
    """
    try:
        return build("alertcenter", "v1beta1", credentials=credentials)
    except Exception as e:
        logger.error(f"Failed to build Google API service: {str(e)}")
        raise
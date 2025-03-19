#!/usr/bin/env python3
"""
Google Workspace Alerts wodle for Wazuh integration.

This script fetches Google Workspace alerts and forwards
them to Wazuh for security monitoring and alerting.
"""
import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from socket import socket, AF_UNIX, SOCK_DGRAM
from typing import Dict, List, Tuple, Optional, Any
from googleapiclient.discovery import Resource
from google_api import authenticate, get_alerts_service
from logger import setup_logger, cleanup_logger
from state_manager import read_state, update_state

from config import (
    WODLE_NAME, GOOGLE_ALERT_TYPES, MAX_STORED_ALERT_IDS,
    DEFAULT_LOG_FILE, DEFAULT_STATE_FILE, DEFAULT_SOCKET_PATH, DEFAULT_CONFIG_FILE
)

class GoogleWorkspaceAlertsWodle:
    """Handle Google Workspace Alerts processing and integration with Wazuh."""

    def __init__(
        self,
        log_file: str,
        log_level: int,
        state_file: str,
        socket_path: str
    ) -> None:
        """
        Initialize the wodle with configuration parameters.

        Args:
            log_file: Path to the log file
            log_level: Logging level (from logging module)
            state_file: Path to the state persistence file
            socket_path: Path to the Wazuh socket

        Returns:
            None
        """
        self.log_file = log_file
        self.log_level = log_level
        self.state_file = state_file
        self.socket_path = socket_path
        self.logger = setup_logger(WODLE_NAME, log_file, log_level)
        self.google_api_config = None

    def set_google_api_config(self, config: Dict[str, str]) -> None:
        """
        Set the Google API configuration from the config file.

        Args:
            config: Dictionary containing configuration parameters

        Returns:
            None
        """
        self.google_api_config = {
            "project_id": config.get("project_id"),
            "private_key_id": config.get("private_key_id"),
            "private_key": config.get("private_key"),
            "client_email": config.get("client_email"),
            "client_id": config.get("client_id"),
            "client_x509_cert_url": config.get("client_x509_cert_url"),
            "delegated_account": config.get("delegated_account")
        }

    def run(self) -> int:
        """
        Main execution method.

        Returns:
            int: Exit code (0 for success, 130 for keyboard interrupt, 1 for other errors)

        Raises:
            KeyboardInterrupt: If the process is interrupted by the user
            Exception: For any other errors during execution
        """
        try:
            self.logger.info("Google Workspace Alerts wodle started")

            # Check if running with proper permissions
            if os.geteuid() != 0 and Path(self.socket_path).is_relative_to("/var/ossec"):
                self.logger.warning("This wodle may require root privileges to access Wazuh socket")

            # Process Google Workspace alerts
            alert_count = self._process_alerts()
            self.logger.info(f"Google Workspace Alerts wodle completed. Processed {alert_count} alerts.")
            return 0
        except KeyboardInterrupt:
            self.logger.info("Process interrupted by user")
            return 130
        except Exception as e:
            self.logger.error(f"Error in execution: {str(e)}")
            return 1
        finally:
            cleanup_logger(self.logger)

    def _process_alerts(self) -> int:
        """
        Process Google Workspace alerts with state persistence.

        Returns:
            int: Number of alerts processed

        Raises:
            Exception: For any errors during alert processing
        """
        try:
            self.logger.info("Starting to fetch Google Workspace alerts")

            # Get state, authenticate, and set up time window
            last_processed_time, processed_alert_ids = read_state(
                self.state_file, MAX_STORED_ALERT_IDS, self.logger
            )

            fetch_end_time = datetime.datetime.now(datetime.timezone.utc)

            # Resume from last run or fetch alerts from the last 24 hours if no state found
            if last_processed_time:
                fetch_start_time = last_processed_time
                self.logger.info(f"Resuming from last run at {fetch_start_time.isoformat()}")
            else:
                fetch_start_time = fetch_end_time - datetime.timedelta(days=1)
                self.logger.info(f"No previous state found - fetching alerts from the last 24 hours")

            # Get the Google API service
            credentials = authenticate(self.google_api_config, self.logger)
            service = get_alerts_service(credentials, self.logger)

            # Process all pages of alerts
            processed_alerts = 0
            newly_processed_ids = set()
            latest_time = None
            next_page_token = None

            while True:
                alerts, next_page_token = self._fetch_alerts_page(
                    service, fetch_start_time, fetch_end_time, next_page_token
                )

                for alert in alerts:
                    alert_id = alert.get('alertId', '')

                    # Skip already processed
                    if alert_id in processed_alert_ids:
                        continue

                    # Track timestamp
                    alert_time = self._get_alert_timestamp(alert)
                    if alert_time and (latest_time is None or alert_time > latest_time):
                        latest_time = alert_time

                    # Process the alert
                    success = self._process_single_alert(alert)
                    if success:
                        newly_processed_ids.add(alert_id)
                        processed_alerts += 1

                if not next_page_token:
                    break

            # Update state
            if latest_time and newly_processed_ids:
                update_state(
                    latest_time,
                    processed_alert_ids.union(newly_processed_ids),
                    self.state_file,
                    MAX_STORED_ALERT_IDS,
                    self.logger
                )

            return processed_alerts

        except Exception as e:
            self.logger.error(f"Error in process_alerts: {str(e)}", exc_info=True)
            return 0

    def _process_single_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Process a single Google Workspace alert and send to Wazuh.

        Args:
            alert: The alert data from Google API

        Returns:
            bool: True if the alert was successfully processed, False otherwise

        Raises:
            Exception: For any errors during alert processing
        """
        try:
            alert_id = alert.get('alertId', 'unknown')
            alert_type = alert.get('type', '')

            self.logger.info(f"Processing alert: {alert_id} - Type: {alert_type}")

            # Check if we should process this alert type
            if alert_type not in GOOGLE_ALERT_TYPES:
                self.logger.info(f"Skipping unsupported Google Alert Type: {alert_type}")
                return False

            # Create base alert structure
            workspace_alert = {
                "wodle": WODLE_NAME,
                "customerId": alert.get('customerId', ''),
                "alertId": alert_id,
                "type": alert_type,
                "source": alert.get('source', ''),
                "createTime": alert.get('createTime', ''),
                "startTime": alert.get('startTime', ''),
                "endTime": alert.get('endTime', ''),
            }

            # Add metadata and data payload
            if alert.get('metadata'):
                workspace_alert["severity"] = alert.get('metadata', {}).get('severity', 'UNKNOWN')
                workspace_alert["status"] = alert.get('metadata', {}).get('status', 'UNKNOWN')

            if alert.get('data'):
                workspace_alert["alert_data"] = alert.get('data', {})

            # Send to Wazuh
            self.logger.info(f"Sending alert to Wazuh: {alert_id}")
            return self._send_event(workspace_alert)

        except Exception as e:
            self.logger.error(f"Error processing alert {alert.get('alertId', '')}: {str(e)}")
            return False

    def _get_alert_timestamp(self, alert: Dict[str, Any]) -> Optional[datetime.datetime]:
        """
        Extract the timestamp from an alert.

        Args:
            alert: The alert data

        Returns:
            Optional[datetime.datetime]: datetime object or None if invalid

        Raises:
            ValueError: If timestamp format is invalid
        """
        create_time_str = alert.get('createTime', '')
        if not create_time_str:
            return None

        try:
            return datetime.datetime.fromisoformat(create_time_str.replace('Z', '+00:00'))
        except ValueError:
            self.logger.warning(f"Invalid timestamp format: {create_time_str}")
            return None

    def _fetch_alerts_page(
        self,
        service: Resource,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
        page_token: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Fetch a page of alerts from the Google API.

        Args:
            service: The Google API service
            start_time: Start time for fetching alerts
            end_time: End time for fetching alerts
            page_token: Token for pagination

        Returns:
            Tuple[List[Dict[str, Any]], Optional[str]]: Tuple containing (alerts, next_page_token)

        Raises:
            googleapiclient.errors.HttpError: If Google API request fails
        """
        query_filter = (
            f'createTime >= "{start_time.isoformat()}" AND '
            f'createTime < "{end_time.isoformat()}"'
        )

        # Add alert types filter
        alert_types = ' OR '.join([f'type="{t}"' for t in GOOGLE_ALERT_TYPES])
        query_filter += f' AND ({alert_types})'

        # Call API
        response = service.alerts().list(
            pageToken=page_token,
            pageSize=100,
            filter=query_filter,
            orderBy="createTime asc"
        ).execute()

        return response.get('alerts', []), response.get('nextPageToken')

    def _flatten_json(self, nested_json: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
        """
        Flatten a nested JSON object with dot notation for keys.

        Args:
            nested_json: Nested JSON object
            prefix: Prefix for the flattened keys

        Returns:
            Dict[str, Any]: Flattened dictionary
        """
        flattened = {}

        for key, value in nested_json.items():
            new_key = f"{prefix}{key}" if prefix else key

            if isinstance(value, dict):
                flattened.update(self._flatten_json(value, f"{new_key}."))
            elif isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                for i, item in enumerate(value):
                    flattened.update(self._flatten_json(item, f"{new_key}.{i}."))
            else:
                flattened[new_key] = value

        return flattened

    def _send_event(self, event: Dict[str, Any]) -> bool:
        """
        Send event to Wazuh socket.

        Args:
            event: Event data to send to Wazuh

        Returns:
            bool: True if successful, False otherwise

        Raises:
            Exception: For any errors when sending the event
        """
        if not event:
            self.logger.error("Attempted to send empty event")
            return False

        sock = None
        try:
            sock = socket(AF_UNIX, SOCK_DGRAM)

            # Verify socket path
            if not Path(self.socket_path).exists():
                self.logger.error(f"Socket path does not exist: {self.socket_path}")
                return False

            # Flatten before sending as it can contain multiple layers of nested JSON object, which Wazuh doesn't seem to support
            flattened_event = self._flatten_json(event)
            message = f"1:{WODLE_NAME}:{json.dumps(flattened_event)}"

            sock.connect(self.socket_path)
            sock.send(message.encode())

            self.logger.debug(f"Event sent: {message[:100]}..." if len(message) > 100 else message)
            return True
        except Exception as e:
            self.logger.error(f"Error sending event: {str(e)}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.error(f"Error closing socket: {str(e)}")

def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(description='Google Workspace Alerts Wodle for Wazuh')
    parser.add_argument(
        '--config',
        default=DEFAULT_CONFIG_FILE,
        help='Path to config JSON file (default: %(default)s)'
    )
    return parser.parse_args()

def main() -> int:
    """
    Script entry point.

    Returns:
        int: Exit code (0 for success, non-zero for errors)

    Raises:
        FileNotFoundError: If config file is not found
        json.JSONDecodeError: If config file contains invalid JSON
        Exception: For any other errors
    """
    # Parse command line arguments
    args = parse_args()

    try:
        # Load configuration from JSON file
        with Path(args.config).open('r') as f:
            config = json.load(f)

        # Get configuration settings with defaults
        log_file = config.get('log_file', DEFAULT_LOG_FILE)
        log_level_name = config.get('log_level', 'INFO')
        log_level = getattr(logging, log_level_name.upper(), logging.INFO)
        state_file = config.get('state_file', DEFAULT_STATE_FILE)
        socket_path = config.get('socket_path', DEFAULT_SOCKET_PATH)

        # Initialize wodle
        wodle = GoogleWorkspaceAlertsWodle(
            log_file=log_file,
            log_level=log_level,
            state_file=state_file,
            socket_path=socket_path
        )

        # Pass the config to the wodle
        wodle.set_google_api_config(config)

        return wodle.run()
    except FileNotFoundError:
        sys.stderr.write(f"Error: Config file not found: {args.config}\n")
        return 1
    except json.JSONDecodeError:
        sys.stderr.write(f"Error: Invalid JSON in config file: {args.config}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Fatal error: {str(e)}\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
"""
State management for tracking processed alerts.
"""
import datetime
import json
import logging
from pathlib import Path
from typing import Optional, Set, Tuple

def read_state(state_file: str, max_stored_ids: int, logger: logging.Logger) -> Tuple[Optional[datetime.datetime], Set[str]]:
    """
    Read the previous state from a persistent file.

    Args:
        state_file: Path to the state file
        max_stored_ids: Maximum number of alert IDs to store
        logger: Logger instance for logging

    Returns:
        Tuple[Optional[datetime.datetime], Set[str]]:
            - The timestamp of the last processed alert or None if not available
            - Set of already processed alert IDs

    Raises:
        ValueError: If timestamp format in state file is invalid
        Exception: For any other errors when reading the state file
    """
    state_file_path = Path(state_file)

    if not state_file_path.exists():
        return None, set()

    try:
        with open(state_file_path, 'r') as f:
            state_data = json.load(f)

        # Parse timestamp and alert IDs
        last_time = None
        if 'last_processed_time' in state_data:
            try:
                last_time = datetime.datetime.fromisoformat(
                    state_data['last_processed_time'].replace('Z', '+00:00')
                )
            except ValueError:
                logger.warning("Invalid timestamp in state file")

        processed_ids = set(state_data.get('processed_alert_ids', [])[-max_stored_ids:])

        return last_time, processed_ids
    except Exception as e:
        logger.error(f"Error reading state file: {str(e)}")
        return None, set()

def update_state(latest_time: datetime.datetime, processed_ids: Set[str],
                state_file: str, max_stored_ids: int, logger: logging.Logger) -> bool:
    """
    Update the state file with the latest information.

    Args:
        latest_time: The timestamp of the latest processed alert
        processed_ids: Set of processed alert IDs
        state_file: Path to the state file
        max_stored_ids: Maximum number of alert IDs to store
        logger: Logger instance for logging

    Returns:
        bool: True if state was successfully updated, False otherwise

    Raises:
        IOError: If there is an I/O error when writing the state file
        Exception: For any other errors when updating the state file
    """
    if not latest_time:
        return False

    state_file_path = Path(state_file)
    state_file_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Prepare state data
        processed_list = list(processed_ids)
        if len(processed_list) > max_stored_ids:
            processed_list = processed_list[-max_stored_ids:]

        state_data = {
            'last_processed_time': latest_time.isoformat(),
            'processed_alert_ids': processed_list
        }

        # Atomic write
        temp_file = state_file_path.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(state_data, f)

        temp_file.replace(state_file_path)
        return True
    except Exception as e:
        logger.error(f"Error updating state file: {str(e)}")
        return False
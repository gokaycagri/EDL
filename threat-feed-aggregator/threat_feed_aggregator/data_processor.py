from datetime import datetime, timezone
from .parsers import parse_text, parse_json, parse_csv
from .db_manager import upsert_indicators_bulk

def process_data(raw_data, data_format="text", key_or_column=None):
    """
    Processes raw data by parsing it and updating the indicators database.

    Args:
        raw_data (str): A string containing the raw data.
        data_format (str): The format of the data (text, json, csv).
        key_or_column: The key for JSON objects or the column index for CSV.

    Returns:
        int: The count of processed items.
    """
    if not raw_data:
        return 0

    items = []
    if data_format == "text":
        items = parse_text(raw_data)
    elif data_format == "json":
        items = parse_json(raw_data, key=key_or_column)
    elif data_format == "csv":
        items = parse_csv(raw_data, column=key_or_column)

    if items:
        upsert_indicators_bulk(items)
    
    return len(items)
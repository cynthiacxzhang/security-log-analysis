# parser.py
import re
from datetime import datetime

def parse_log_line(line: str) -> dict:
    """
    Parses a log line of the format:
      'YYYY-MM-DD HH:MM:SS, IP=xxx.xxx.xxx.xxx, EVENT=..., USER=...'
    into a Python dict. Returns None if it doesn't match.
    """
    pattern = (r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), '
               r'IP=(?P<ip>[\d\.]+), '
               r'EVENT=(?P<event>[A-Z_]+), '
               r'USER=(?P<user>\w+)')

    match = re.search(pattern, line)
    if match:
        data = match.groupdict()
        data['timestamp'] = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
        return data
    else:
        return None

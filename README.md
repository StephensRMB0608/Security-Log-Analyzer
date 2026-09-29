# Security Log Analyzer

A Python security tool that reads login records from a log file, counts successful and failed login attempts for each IP address, and identifies IP addresses that reach a failed-login threshold.

The analyzer also handles malformed entries and reports when no suspicious activity or log data is found.

# Features of the Security Log Analyzer:

- Reads login events from a text file.
- Tracks failed and successful logins separately for each IP address.
- Flags IP addresses with five or more failed login attempts.
- Skips blank lines safely.
- Reports malformed entries and unsupported login statuses.
- Displays login statistics and security alerts.
- Handles empty log files.
- Includes seven automated unit tests.

# The Project Structure:

- analyzer.py — contains the log-analysis, suspicious-IP detection, reporting, and main application logic.
- sample_logs.txt — contains sample login events for the analyzer.
- test_analyzer.py — contains automated unit tests.
- README.md — explains the project and how to use it.

# Requirements for the Security Log Analyzer:

- Python 3.8 or newer
- No third-party packages are required

The project uses only modules from Python’s standard library.

# Log Format:

Each valid log entry must contain exactly two whitespace-separated values:

text:
<IP_ADDRESS> <LOGIN_STATUS>


The supported statuses are:

- 'LOGIN_FAILED'
- 'LOGIN_SUCCESS'

Example:

'''text
10.0.0.5 LOGIN_FAILED
10.0.0.8 LOGIN_SUCCESS
10.0.0.5 LOGIN_FAILED
'''

Blank lines are ignored. Entries with the wrong number of values or an unsupported status are skipped with a warning.

# How It Works

1. The program opens sample_logs.txt.
2. It reads and validates every log entry.
3. It creates a dictionary entry for each valid IP address.
4. It counts failed and successful login attempts separately.
5. It identifies IP addresses with five or more failed logins.
6. It displays the login statistics and security alerts.

An IP reaching the threshold is treated as suspicious. This does not prove that the IP is malicious.

# How to test the Analyser:

Open a terminal in the project directory.

On Windows:

'''powershell
py analyzer.py
'''

On macOS or Linux:

'''bash
python3 analyzer.py
'''

# Example Output:

'''text
{'10.0.0.5': {'failed_login': 5,
              'successful_login': 1},
 '10.0.0.8': {'failed_login': 2,
              'successful_login': 1}}

Suspicious activity:
SECURITY ALERT: 10.0.0.5 produced 5 failed login attempts.
'''

If valid records exist but no IP reaches the threshold:

'''text
No suspicious activity detected.
'''

If the log file is empty:

'''text
No log entries found.
'''

# Running the Tests:

On Windows:

'''powershell
py -m unittest -v test_analyzer.py
'''

On macOS or Linux:

'''bash
python3 -m unittest -v test_analyzer.py
'''

# Test Coverage:

The seven automated tests verify:

- An IP exactly at the threshold is suspicious.
- An IP below the threshold is not suspicious.
- Multiple suspicious IP addresses are returned.
- Failed and successful login attempts are counted correctly.
- Empty log files return an empty dictionary.
- Different IP addresses receive separate counters.
- Blank, malformed, and unsupported entries are skipped.

# Future Improvements that can be applied on the project:

- Allow the threshold to be configured from the command line.
- Use timestamps to detect repeated failures within a specific time window.
- Analyze real operating-system or authentication logs.
- Export alerts to a text, CSV, or JSON report.
- Validate that each IP address has a legitimate IPv4 or IPv6 format.
- Replace printed warnings with Python’s logging system.

# Learning Outcomes:

Through this project, I learned how security logs can be parsed, monitored, and used to identify suspicious activity.

I strengthened my understanding of dictionaries, functions, file handling, validation, error handling, thresholds, and modular program design. I also learned why manual and automated testing are important for verifying that security logic behaves correctly and continues working after changes.

Building this project increased my confidence and strengthened my interest in cybersecurity and security engineering.

# Author:

Stephens Rankwane.
GitHub: [StephensRMB0608](https://github.com/StephensRMB0608)
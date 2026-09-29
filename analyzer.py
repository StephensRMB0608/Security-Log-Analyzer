from pathlib import Path
from pprint import pprint

FAILED_LOGIN_THRESHOLD = 5

def analyze_logs(log_file):
    login_attempts = {}

    with log_file.open(encoding = "utf-8") as file:
        """This function analyze login entries and return counts mapped to IP address"""
        for line_number, line in enumerate(file, start=1):
            cleaned_line = line.strip()

            if not cleaned_line:
                continue

            parts = cleaned_line.split()

            if len(parts) != 2:
                print(f"WARNING: Skipping invalid entry on line {line_number}: {cleaned_line}!!")
                continue

            ip_address, login_status = parts

            if login_status not in ("LOGIN_FAILED", "LOGIN_SUCCESS"):
                print(f"WARNING: Skipping unknown status on line {line_number}: {login_status}")
                continue

            if ip_address not in login_attempts:
                login_attempts[ip_address] = {
                    "failed_login": 0,
                    "successful_login": 0 
                }

            if login_status == "LOGIN_FAILED":
                login_attempts[ip_address]["failed_login"] += 1

            elif login_status == "LOGIN_SUCCESS":
                login_attempts[ip_address]["successful_login"] += 1

    return login_attempts

def add_suspicious_ips(login_attempts, threshold):
    """This function returns IP addresses that met the threshols for the failed-login count"""
    suspicious_ips = {}

    for ip_address, counts in login_attempts.items():
        if counts["failed_login"] >= threshold:
            suspicious_ips[ip_address] = counts["failed_login"]

    return suspicious_ips

def display_report(login_attempts, suspicious_ips):
    """This function display login counts and any other suspicious IP addresses."""
    if not login_attempts:
        print("\nNo login entries found.")

    else:
        pprint(login_attempts, sort_dicts=False, width=40)

        if suspicious_ips:
            print("\nSuspicious activity:")

            for ip_address, failed_count in suspicious_ips.items():
                print(f"EMERGENCY ALERT: {ip_address} produced {failed_count} failed login attepts!!!")
                 
        else:
            print("\nNo suspicious activity detected!!!")
                 
def main():
    """This function runs the security log analyzer"""
    log_file = Path(__file__).parent / "sample_logs.txt"
    login_attempts = analyze_logs(log_file)

    suspicious_ips = add_suspicious_ips(login_attempts, FAILED_LOGIN_THRESHOLD)

    display_report(login_attempts, suspicious_ips)

if __name__ == "__main__":
    main()
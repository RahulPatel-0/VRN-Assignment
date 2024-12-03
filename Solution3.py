def find_suspicious_ips(log_file_path, max_attempts=10):
    """
    Identify IPs with excessive failed login attempts in the log file.

    Parameters:
        log_file_path (str): Path to the server log file.
        max_attempts (int): Threshold for flagging suspicious activity (default: 10).

    Returns:
        None: Outputs the flagged IPs and their attempt counts to the console.
    """
    from collections import defaultdict

    # Dictionary to track failed login attempts per IP
    suspicious_ips = defaultdict(int)

    try:
        # Open and process the log file
        with open(log_file_path, 'r') as log_file:
            for entry in log_file:
                # Parse each log entry
                details = entry.strip().split()
                if not details:
                    continue

                # Extract relevant information
                ip_address = details[0]  # Assuming IP is the first item
                status_code = details[-2] if len(details) > 2 else ""

                # Check for failed login attempts (status code 401 or specific text)
                if status_code == "401" or "Invalid credentials" in entry:
                    suspicious_ips[ip_address] += 1

        # Filter and display flagged IPs
        flagged = {ip: count for ip, count in suspicious_ips.items() if count > max_attempts}
        if flagged:
            print("Suspicious Activity Identified:")
            print(f"{'IP Address':<20}{'Failed Attempts':<20}")
            print("=" * 40)
            for ip, count in sorted(flagged.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip:<20}{count:<20}")
        else:
            print("No suspicious activity found.")

    except FileNotFoundError:
        print(f"Error: Unable to locate the file '{log_file_path}'.")
    except Exception as error:
        print(f"An unexpected error occurred: {error}")


# Example execution
if __name__ == "__main__":
    log_file_name = "server_logs.txt"  # Replace with the actual log file path
    find_suspicious_ips(log_file_name, max_attempts=10)

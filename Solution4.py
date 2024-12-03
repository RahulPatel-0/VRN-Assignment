import csv
from collections import Counter


def analyze_ip_requests(log_file):
    """
    Analyze the number of requests made by each IP address.

    Parameters:
        log_file (str): Path to the log file.

    Returns:
        Counter: A Counter object with IP addresses as keys and request counts as values.
    """
    ip_tracker = Counter()

    try:
        with open(log_file, 'r') as file:
            for entry in file:
                data = entry.strip().split()
                if not data:
                    continue
                client_ip = data[0]  # IP is assumed to be the first column
                ip_tracker[client_ip] += 1
    except Exception as e:
        print(f"Error processing IP requests: {e}")

    return ip_tracker


def determine_top_endpoint(log_file):
    """
    Identify the endpoint accessed most frequently.

    Parameters:
        log_file (str): Path to the log file.

    Returns:
        tuple: The most accessed endpoint and the number of accesses.
    """
    endpoint_counter = Counter()

    try:
        with open(log_file, 'r') as file:
            for entry in file:
                if '"' in entry:
                    segments = entry.split('"')
                    if len(segments) > 1:
                        request_info = segments[1].split()
                        if len(request_info) > 1:
                            endpoint = request_info[1]
                            endpoint_counter[endpoint] += 1
    except Exception as e:
        print(f"Error processing endpoint data: {e}")

    if endpoint_counter:
        popular_endpoint = endpoint_counter.most_common(1)[0]
        return popular_endpoint
    return None, 0


def flag_suspicious_ips(log_file, max_failed_attempts=10):
    """
    Identify suspicious IPs based on failed login attempts.

    Parameters:
        log_file (str): Path to the log file.
        max_failed_attempts (int): Threshold for flagging IPs (default: 10).

    Returns:
        dict: IPs flagged for suspicious activity and their failed attempt counts.
    """
    failed_logins = Counter()

    try:
        with open(log_file, 'r') as file:
            for entry in file:
                data = entry.strip().split()
                if not data:
                    continue
                client_ip = data[0]
                if "401" in entry or "Invalid credentials" in entry:
                    failed_logins[client_ip] += 1
    except Exception as e:
        print(f"Error detecting suspicious activity: {e}")

    return {ip: attempts for ip, attempts in failed_logins.items() if attempts > max_failed_attempts}


def export_to_csv(ip_stats, endpoint_info, flagged_ips, output_file):
    """
    Export the analysis results to a CSV file.

    Parameters:
        ip_stats (Counter): IP request counts.
        endpoint_info (tuple): The most accessed endpoint and its access count.
        flagged_ips (dict): Flagged IPs and their failed attempt counts.
        output_file (str): Filepath for the output CSV.

    Returns:
        None
    """
    try:
        with open(output_file, mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)

            # Section: Requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_stats.items():
                writer.writerow([ip, count])

            writer.writerow([])  # Blank line for spacing

            # Section: Most Accessed Endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([endpoint_info[0], endpoint_info[1]])

            writer.writerow([])  # Blank line for spacing

            # Section: Suspicious Activity
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in flagged_ips.items():
                writer.writerow([ip, count])

        print(f"Results successfully saved to {output_file}")

    except Exception as e:
        print(f"Error writing to CSV file: {e}")


# Main script execution
if __name__ == "__main__":
    log_file_path = "server_logs.txt"  # Specify your log file path here
    output_csv_file = "log_analysis_output.csv"

    # Perform analyses
    ip_requests = analyze_ip_requests(log_file_path)
    top_endpoint, top_endpoint_count = determine_top_endpoint(log_file_path)
    suspicious_ips = flag_suspicious_ips(log_file_path, max_failed_attempts=10)

    # Display results
    print("\nIP Address Requests:")
    for ip, count in ip_requests.items():
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{top_endpoint}: {top_endpoint_count} accesses")

    print("\nSuspicious IPs Detected:")
    for ip, attempts in suspicious_ips.items():
        print(f"{ip}: {attempts} failed login attempts")

    # Save results to a CSV
    export_to_csv(ip_requests, (top_endpoint, top_endpoint_count), suspicious_ips, output_csv_file)

def analyze_logs(log_path):
    """
    Analyze the log file to determine the request count for each IP address.

    Parameters:
        log_path (str): Path to the log file to be processed.

    Returns:
        None: Prints a sorted table of IP addresses and their request counts.
    """
    from collections import Counter

    # Dictionary to store IP and corresponding request counts
    ip_request_count = Counter()

    try:
        # Open the file and process line by line
        with open(log_path, 'r') as log_file:
            for record in log_file:
                # Extract IP address (assuming it's the first segment of each log line)
                segments = record.strip().split()
                if segments:
                    ip_address = segments[0]
                    ip_request_count[ip_address] += 1

        # Sort IPs by request counts in descending order
        sorted_counts = sorted(ip_request_count.items(), key=lambda pair: pair[1], reverse=True)

        # Print the results in a tabular format
        print(f"{'IP Address':<20}{'Requests':<10}")
        print("=" * 30)
        for address, count in sorted_counts:
            print(f"{address:<20}{count:<10}")

    except FileNotFoundError:
        print(f"Error: Unable to locate the file at '{log_path}'")
    except Exception as error:
        print(f"Unexpected error: {error}")


# Example of script usage
if __name__ == "__main__":
    file_path = "server_logs.txt"  # Change this to the path of your log file
    analyze_logs(file_path)

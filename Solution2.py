def log_analysis(filepath):
    """
    Processes the log file to:
    1. Count requests made by each IP address.
    2. Identify the most accessed endpoint.

    Parameters:
        filepath (str): Path to the log file.

    Returns:
        None: Outputs results to the console.
    """
    from collections import defaultdict

    # Data structures to store counts
    ip_tracker = defaultdict(int)
    endpoint_tracker = defaultdict(int)

    try:
        # Read the log file
        with open(filepath, 'r') as file:
            for line in file:
                parts = line.strip().split()
                if not parts:
                    continue

                # Extract IP address
                ip = parts[0]
                ip_tracker[ip] += 1

                # Extract endpoint (assuming it's in quotes)
                if '"' in line:
                    sections = line.split('"')
                    if len(sections) > 1:
                        request_data = sections[1].split()
                        if len(request_data) > 1:
                            endpoint = request_data[1]
                            endpoint_tracker[endpoint] += 1

        # Display IP address counts
        print(f"{'IP Address':<20}{'Request Count':<10}")
        print("=" * 35)
        for ip, count in sorted(ip_tracker.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<20}{count:<10}")

        print("\n")

        # Identify the most accessed endpoint
        if endpoint_tracker:
            top_endpoint = max(endpoint_tracker, key=endpoint_tracker.get)
            print(f"Most Frequently Accessed Endpoint:\n{top_endpoint} (Accessed {endpoint_tracker[top_endpoint]} times)")
        else:
            print("No endpoint data available.")

    except FileNotFoundError:
        print(f"Error: The file at '{filepath}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Example execution
if __name__ == "__main__":
    log_file = "server_logs.txt"  # Change to your log file path
    log_analysis(log_file)

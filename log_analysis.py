import re
from collections import defaultdict
import csv
import os
import logging
from typing import Dict, Tuple, List


class LogAnalyzer:
    def __init__(self, log_file_path: str, suspicious_threshold: int = 5):
        """
        Initialize the log analyzer with configuration parameters.

        :param log_file_path: Path to the log file to be analyzed
        :param suspicious_threshold: Number of failed login attempts to consider an IP suspicious
        """
        self.log_file_path = log_file_path
        self.suspicious_threshold = suspicious_threshold

        # Setup logging
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def parse_log_file(self) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
        """
        Parse the log file and extract detailed metrics.

        :return: Tuple of dictionaries containing IP request counts,
                 endpoint counts, and failed login attempts
        """
        ip_request_count = defaultdict(int)
        endpoint_count = defaultdict(int)
        failed_login_attempts = defaultdict(int)

        # More comprehensive regex to capture more log formats
        log_pattern = re.compile(
            r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*'
            r'"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+[^"]*"\s+'
            r'(?P<status>\d{3})'
        )

        try:
            with open(self.log_file_path, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    match = log_pattern.search(line)
                    if match:
                        ip = match.group('ip')
                        method = match.group('method')
                        endpoint = match.group('endpoint')
                        status = int(match.group('status'))

                        ip_request_count[ip] += 1
                        endpoint_count[endpoint] += 1

                        # More precise failed login detection
                        if method in ['POST', 'PUT'] and status in [401, 403]:
                            failed_login_attempts[ip] += 1
                    else:
                        self.logger.warning(f"Unparseable log line at line {line_num}: {line.strip()}")

        except FileNotFoundError:
            self.logger.error(f"Log file not found: {self.log_file_path}")
            raise
        except PermissionError:
            self.logger.error(f"Permission denied when accessing log file: {self.log_file_path}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error parsing log file: {e}")
            raise

        return ip_request_count, endpoint_count, failed_login_attempts

    def find_most_accessed_endpoint(self, endpoint_count: Dict[str, int]) -> Tuple[str, int]:
        """
        Find the most frequently accessed endpoint.

        :param endpoint_count: Dictionary of endpoint access counts
        :return: Tuple of most accessed endpoint and its count
        """
        if not endpoint_count:
            return "No endpoints found", 0
        return max(endpoint_count.items(), key=lambda x: x[1])

    def detect_suspicious_ips(self, failed_login_attempts: Dict[str, int]) -> Dict[str, int]:
        """
        Detect IPs with suspicious login behavior.

        :param failed_login_attempts: Dictionary of failed login attempts per IP
        :return: Dictionary of suspicious IPs and their failed attempt counts
        """
        return {
            ip: count
            for ip, count in failed_login_attempts.items()
            if count >= self.suspicious_threshold
        }

    def save_results_to_csv(self,
                            ip_request_count: Dict[str, int],
                            most_accessed_endpoint: Tuple[str, int],
                            suspicious_ips: Dict[str, int],
                            output_csv_file: str):
        """
        Save analysis results to a CSV file.

        :param ip_request_count: IP request counts
        :param most_accessed_endpoint: Most accessed endpoint details
        :param suspicious_ips: Suspicious IPs
        :param output_csv_file: Path to output CSV file
        """
        try:
            with open(output_csv_file, mode='w', newline='') as file:
                writer = csv.writer(file)

                # IP Address Request Counts
                writer.writerow(["IP Address", "Request Count"])
                for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
                    writer.writerow([ip, count])

                writer.writerow([])  # Separation

                # Most Accessed Endpoint
                writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
                writer.writerow(list(most_accessed_endpoint))

                writer.writerow([])  # Separation

                # Suspicious Activity
                writer.writerow(["Suspicious IP", "Failed Login Count"])
                if suspicious_ips:
                    for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                        writer.writerow([ip, count])
                else:
                    writer.writerow(["No suspicious activity detected", "N/A"])

            self.logger.info(f"Results saved to {output_csv_file}")
        except IOError as e:
            self.logger.error(f"Error writing to CSV: {e}")

    def analyze_log(self, output_csv_file: str = 'log_analysis_results.csv'):
        """
        Perform complete log analysis.

        :param output_csv_file: Path to output CSV file
        """
        # Parse log file
        ip_request_count, endpoint_count, failed_login_attempts = self.parse_log_file()

        # Find most accessed endpoint
        most_accessed_endpoint = self.find_most_accessed_endpoint(endpoint_count)

        # Detect suspicious IPs
        suspicious_ips = self.detect_suspicious_ips(failed_login_attempts)

        # Save results to CSV
        self.save_results_to_csv(
            ip_request_count,
            most_accessed_endpoint,
            suspicious_ips,
            output_csv_file
        )

        # Print summary
        self._print_summary(
            ip_request_count,
            most_accessed_endpoint,
            suspicious_ips
        )

    def _print_summary(self,
                       ip_request_count: Dict[str, int],
                       most_accessed_endpoint: Tuple[str, int],
                       suspicious_ips: Dict[str, int]):
        """
        Print a detailed summary of log analysis results.

        :param ip_request_count: IP request counts
        :param most_accessed_endpoint: Most accessed endpoint details
        :param suspicious_ips: Suspicious IPs
        """
        print("\n--- Log Analysis Summary ---")

        print("\nTop 5 IP Addresses by Request Count:")
        for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{ip:<20} {count} requests")

        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

        print("\nSuspicious Activity:")
        if suspicious_ips:
            print("Potential security threats detected:")
            for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip:<20} {count} failed login attempts")
        else:
            print("No suspicious activity detected.")


def main():
    # Use the sample.log in the current directory
    log_file_path = 'sample.log'

    try:
        # Initialize and run log analyzer
        analyzer = LogAnalyzer(log_file_path)
        analyzer.analyze_log()
    except Exception as e:
        print(f"An error occurred during log analysis: {e}")


if __name__ == "__main__":
    main()
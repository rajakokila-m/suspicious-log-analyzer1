import collections

FAILED_KEYWORD = "FAILED_LOGIN"
THRESHOLD = 5  # failed logins before flagging


def parse_log(path):
    """Reads log file line by line."""
    with open(path, "r") as f:
        for line in f:
            yield line.strip()


def find_suspicious_ips(log_lines):
    """Counts failed login attempts per IP."""
    failed_counts = collections.Counter()

    for line in log_lines:
        if FAILED_KEYWORD in line:
            # assume log format: "IP - TIMESTAMP - EVENT"
            parts = line.split(" - ")
            ip = parts[0]
            failed_counts[ip] += 1

    # Only return IPs that meet or exceed the threshold
    return {ip: count for ip, count in failed_counts.items() if count >= THRESHOLD}


def write_report(suspicious_ips, report_path):
    """Writes the output report."""
    with open(report_path, "w") as f:
        f.write("Suspicious IP Report\n")
        f.write("====================\n\n")

        if not suspicious_ips:
            f.write("No suspicious IPs found.\n")
            return

        for ip, count in suspicious_ips.items():
            f.write(f"{ip} triggered {count} failed logins.\n")


if __name__ == "__main__":
    log_path = "sample_logs/access.log"
    report_path = "reports/report.txt"

    lines = list(parse_log(log_path))
    suspicious_ips = find_suspicious_ips(lines)
    write_report(suspicious_ips, report_path)

    print(f"Report generated: {report_path}")

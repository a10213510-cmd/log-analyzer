import re
import json
from collections import Counter
from pathlib import Path
from datetime import datetime

# Example:
# Mar  5 10:12:34 myhost sshd[1111]: Failed password ... from 203.0.113.10 ...
FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+.*sshd\[\d+\]: Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def analyze_failed(log_path: str | Path):
    log_path = Path(log_path)
    failed_by_ip = Counter()
    failed_by_hour = Counter()

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if not m:
                continue

            ip = m.group("ip")
            hour = int(m.group("time").split(":")[0])

            failed_by_ip[ip] += 1
            failed_by_hour[hour] += 1

    return failed_by_ip, failed_by_hour

def print_hour_histogram(failed_by_hour: Counter):
    print("\n[Failed Events by Hour]")
    if not failed_by_hour:
        print("  (no data)")
        return

    max_count = max(failed_by_hour.values())
    # bar length up to 30 chars
    scale = 30 / max_count if max_count > 0 else 1

    for h in range(24):
        c = failed_by_hour.get(h, 0)
        bar = "█" * int(c * scale) if c > 0 else ""
        print(f"  {h:02d}:00  {c:3d}  {bar}")

def write_json_report(
    log_file: str,
    failed_by_ip: Counter,
    failed_by_hour: Counter,
    top_n: int,
    brute_threshold: int,
    out_path: str | Path = "reports/report.json",
):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    top_failed = [{"ip": ip, "count": c} for ip, c in failed_by_ip.most_common(top_n)]
    brute_force = [{"ip": ip, "count": c} for ip, c in failed_by_ip.items() if c >= brute_threshold]
    hourly = [{"hour": h, "count": failed_by_hour.get(h, 0)} for h in range(24)]

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_log": str(log_file),
        "settings": {"top": top_n, "brute_threshold": brute_threshold},
        "summary": {
            "unique_failed_ips": len(failed_by_ip),
            "total_failed_events": sum(failed_by_ip.values()),
            "brute_force_ip_count": len(brute_force),
        },
        "top_failed_ips": top_failed,
        "brute_force_suspects": sorted(brute_force, key=lambda x: x["count"], reverse=True),
        "failed_events_by_hour": hourly,
    }

    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path

def main():
    import argparse

    parser = argparse.ArgumentParser(description="SSH log analyzer (failed login focused)")
    parser.add_argument("logfile", help="path to auth.log (or sample log)")
    parser.add_argument("--top", type=int, default=10, help="top N IPs")
    parser.add_argument("--brute", type=int, default=5, help="brute force threshold")
    parser.add_argument("--json", action="store_true", help="export JSON report to reports/report.json")
    args = parser.parse_args()

    failed_by_ip, failed_by_hour = analyze_failed(args.logfile)

    print("=== SSH Failed Login Report ===")
    if not failed_by_ip:
        print("No failed-login lines found.")
        return

    print(f"\n[Top Failed IPs] (top {args.top})")
    for ip, c in failed_by_ip.most_common(args.top):
        flag = "  <-- BRUTE FORCE?" if c >= args.brute else ""
        print(f"{ip:15s} {c:5d}{flag}")

    print_hour_histogram(failed_by_hour)

    if args.json:
        out = write_json_report(
            log_file=args.logfile,
            failed_by_ip=failed_by_ip,
            failed_by_hour=failed_by_hour,
            top_n=args.top,
            brute_threshold=args.brute,
        )
        print(f"\n[JSON] wrote report to: {out}")

if __name__ == "__main__":
    main()
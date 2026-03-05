import re
import json
from collections import Counter
from pathlib import Path
from datetime import datetime

FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def analyze_failed_ips(log_path: str | Path) -> Counter:
    log_path = Path(log_path)
    counts = Counter()

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                counts[m.group("ip")] += 1

    return counts

def write_json_report(
    log_file: str,
    counts: Counter,
    top_n: int,
    brute_threshold: int,
    out_path: str | Path = "reports/report.json",
):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    top_failed = [{"ip": ip, "count": c} for ip, c in counts.most_common(top_n)]
    brute_force = [{"ip": ip, "count": c} for ip, c in counts.items() if c >= brute_threshold]

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_log": str(log_file),
        "settings": {
            "top": top_n,
            "brute_threshold": brute_threshold,
        },
        "summary": {
            "unique_failed_ips": len(counts),
            "total_failed_events": sum(counts.values()),
            "brute_force_ip_count": len(brute_force),
        },
        "top_failed_ips": top_failed,
        "brute_force_suspects": sorted(brute_force, key=lambda x: x["count"], reverse=True),
    }

    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Simple SSH log analyzer")
    parser.add_argument("logfile", help="path to auth.log (or sample log)")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--brute", type=int, default=5, help="brute force threshold")
    parser.add_argument("--json", action="store_true", help="export JSON report to reports/report.json")

    args = parser.parse_args()

    counts = analyze_failed_ips(args.logfile)

    print("=== SSH Failed Login Report ===")

    if not counts:
        print("No failed-login lines found.")
        return

    print(f"\n[Top Failed IPs] (top {args.top})")
    for ip, c in counts.most_common(args.top):
        flag = "  <-- BRUTE FORCE?" if c >= args.brute else ""
        print(f"{ip:15s} {c:5d}{flag}")

    if args.json:
        out = write_json_report(
            log_file=args.logfile,
            counts=counts,
            top_n=args.top,
            brute_threshold=args.brute,
        )
        print(f"\n[JSON] wrote report to: {out}")

if __name__ == "__main__":
    main()
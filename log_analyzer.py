import re
from collections import Counter
from pathlib import Path

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


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Simple SSH log analyzer")
    parser.add_argument("logfile", help="path to auth.log (or sample log)")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--brute", type=int, default=5, help="brute force threshold")

    args = parser.parse_args()

    counts = analyze_failed_ips(args.logfile)

    print("=== SSH Failed Login Report ===")

    if not counts:
        print("No failed-login lines found.")
        return

    print(f"\n[Top Failed IPs] (top {args.top})")

    for ip, c in counts.most_common(args.top):

        if c >= args.brute:
            flag = "  <-- BRUTE FORCE?"
        else:
            flag = ""

        print(f"{ip:15s} {c:5d}{flag}")


if __name__ == "__main__":
    main()
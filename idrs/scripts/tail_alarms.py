#!/usr/bin/env python3
import argparse, sys, json, os, time

def pretty(ev: dict) -> str:
    sev = ev.get("severity_text", "ATTACK")
    pub = ev.get("publisher") or ev.get("publisher_id") or "-"
    goid = ev.get("goID", "-")
    prob = ev.get("probability")
    prob_s = f"{prob:.4f}" if isinstance(prob, (int, float)) else "-"
    body = ev.get("body") or ev.get("explanation") or ""
    ts = ev.get("ts") or "-"
    return f"{ts} {sev} pub={pub} goID={goid} prob={prob_s} {body}"

def matches(ev: dict, filters):
    for k, v in filters.items():
        if str(ev.get(k, "")) != v:
            return False
    return True

def run(path: str, pretty_flag: bool, follow: bool, filters):
    def handle_line(line: str):
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except Exception:
            print(line)
            return
        if filters and not matches(ev, filters):
            return
        print(pretty(ev) if pretty_flag else json.dumps(ev, ensure_ascii=False))

    if path == "-" or path == "":
        for line in sys.stdin:
            handle_line(line)
        return

    with open(path, "r", encoding="utf-8") as f:
        if follow:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                handle_line(line)
        else:
            for line in f:
                handle_line(line)

def main():
    ap = argparse.ArgumentParser(description="Tail/preview JSONL alarm file")
    ap.add_argument("path", help="Path to JSONL file, or '-' for stdin")
    ap.add_argument("--pretty", action="store_true", help="Pretty one-line summary")
    ap.add_argument("--follow", "-f", action="store_true", help="Follow new lines (like tail -f)")
    ap.add_argument("--filter", action="append", default=[],
                    help="Filter key=value (repeatable), e.g., --filter publisher=CBAY")
    args = ap.parse_args()
    filters = {}
    for kv in args.filter:
        if "=" in kv:
            k, v = kv.split("=", 1)
            filters[k] = v
    run(args.path, args.pretty, args.follow, filters)

if __name__ == "__main__":
    main()
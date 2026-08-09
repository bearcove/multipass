#!/usr/bin/python3
import json
import os
import signal
import sys
import time

def write_pid():
    path = os.environ.get("IPERF_FIXTURE_PID_FILE")
    directory = os.environ.get("IPERF_FIXTURE_PID_DIRECTORY")
    if directory:
        path = os.path.join(directory, str(os.getpid()))
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))


def emit(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def final_line(bits_per_second=222.0, byte_count=2222, retransmits=7):
    return {
        "event": "end",
        "data": {
            "streams": [
                {
                    "sender": {"mean_rtt": 11, "max_rtt": 17},
                    "receiver": {},
                }
            ],
            "sum_sent": {"retransmits": retransmits},
            "sum_received": {
                "start": 0,
                "end": 1,
                "bytes": byte_count,
                "bits_per_second": bits_per_second,
            },
        },
    }


def interval(bits_per_second, start=0.0, end=1.0):
    return {
        "event": "interval",
        "data": {
            "sum": {
                "start": start,
                "end": end,
                "bits_per_second": bits_per_second,
                "omitted": False,
            }
        },
    }


write_pid()
mode = os.environ.get("IPERF_FIXTURE_MODE", "success")

if mode == "capture":
    path = os.environ["IPERF_FIXTURE_ARGS_FILE"]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sys.argv[1:], handle)
    emit(interval(111.0))
    emit(final_line())
elif mode == "incremental":
    emit(interval(111.0, 0.0, 1.0))
    with open(os.environ["IPERF_FIXTURE_READY_FILE"], "w", encoding="utf-8"):
        pass
    release_path = os.environ["IPERF_FIXTURE_RELEASE_FILE"]
    release_deadline = time.monotonic() + 5.0
    while not os.path.exists(release_path):
        if time.monotonic() >= release_deadline:
            sys.stderr.write("incremental fixture release timed out\n")
            sys.stderr.flush()
            sys.exit(24)
        time.sleep(0.01)
    emit(interval(222.0, 1.0, 2.0))
    emit(final_line())
elif mode == "large-stderr":
    sys.stderr.write("x" * 10000)
    sys.stderr.write(" stderr-finished\n")
    sys.stderr.flush()
    emit(interval(111.0))
    emit(final_line())
elif mode == "skewed-aggregate":
    target = sys.argv[sys.argv.index("--client") + 1]
    if target.endswith(".1"):
        emit(interval(100.0, 0.15, 1.15))
        emit(interval(110.0, 1.15, 2.15))
    else:
        time.sleep(0.1)
        emit(interval(200.0, 0.85, 1.85))
        time.sleep(0.1)
        emit(interval(220.0, 1.85, 2.85))
    emit(final_line())
elif mode == "malformed-middle-aggregate":
    target = sys.argv[sys.argv.index("--client") + 1]
    if target.endswith(".1"):
        emit(interval(100.0, 0.0, 1.0))
        emit({"event": "interval", "data": {"sum": {"start": 1.0, "end": 2.0, "omitted": False}}})
        emit(interval(110.0, 2.0, 3.0))
    else:
        emit(interval(200.0, 0.0, 1.0))
        emit(interval(210.0, 1.0, 2.0))
        emit(interval(220.0, 2.0, 3.0))
    emit(final_line())
elif mode == "type-malformed-middle-aggregate":
    target = sys.argv[sys.argv.index("--client") + 1]
    if target.endswith(".1"):
        emit(interval(100.0, 0.0, 1.0))
        emit({"event": "interval", "data": {"sum": {"start": 1.0, "end": 2.0, "bits_per_second": "bad", "omitted": False}}})
        emit(interval(110.0, 2.0, 3.0))
    else:
        emit(interval(200.0, 0.0, 1.0))
        emit(interval(210.0, 1.0, 2.0))
        emit(interval(220.0, 2.0, 3.0))
    emit(final_line())
elif mode == "immediate-success":
    emit(final_line())
elif mode == "fail":
    sys.stderr.write(os.environ.get("IPERF_FIXTURE_ERROR", "fixture failed") + "\n")
    sys.stderr.flush()
    sys.exit(int(os.environ.get("IPERF_FIXTURE_EXIT", "23")))
elif mode == "partial-fail":
    target = sys.argv[sys.argv.index("--client") + 1]
    if target.endswith(".2"):
        sys.stderr.write("second member failed\n")
        sys.stderr.flush()
        sys.exit(31)
    emit(interval(100.0))
    emit(final_line(bits_per_second=100.0, byte_count=1000, retransmits=1))
elif mode in ("sleep", "ignore-term"):
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
else:
    emit(interval(111.0))
    emit(final_line())

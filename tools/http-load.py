#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The load for RFC 0086's gate: sixteen keep-alive clients, every body checked.

Each client holds one HTTP/1.1 connection and asks `GET /c<client>/r<n>` in a
loop until the time is up; the server answers `bhaskix <path>\\n`, so a response
meant for another request is a wrong body, not a plausible one. **A connection
that fails is counted and reopened**, never silently retried into a pass: any
error, any wrong body, or no request completed at all is a failing exit.

Throughput and latency are printed and not judged -- the gate is correctness
under sustained load, and the number is reported honestly (RFC 0086).

    tools/http-load.py --port 45562 --seconds 30 [--clients 16]
"""

import argparse
import http.client
import sys
import threading
import time


def client(number, port, deadline, results, lock, run_started):
    connection = None
    request = 0
    latencies = []
    errors = 0
    reconnects = 0
    first_error = None
    error_times = []
    while time.monotonic() < deadline:
        if connection is None:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            reconnects += 1
        path = f"/c{number}/r{request}"
        started = time.monotonic()
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read().decode("utf-8", "replace")
            if response.status != 200 or body != f"bhaskix {path}\n":
                errors += 1
                error_times.append(time.monotonic() - run_started)
                first_error = first_error or f"{path}: status {response.status}, body {body!r}"
        except (OSError, http.client.HTTPException) as error:
            errors += 1
            error_times.append(time.monotonic() - run_started)
            first_error = first_error or f"{path}: {type(error).__name__}: {error}"
            connection.close()
            connection = None
            continue
        latencies.append(time.monotonic() - started)
        request += 1
    if connection is not None:
        connection.close()
    with lock:
        results.append((number, latencies, errors, reconnects - 1, first_error, error_times))


def percentile(sorted_values, fraction):
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, int(fraction * len(sorted_values)))
    return sorted_values[index]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--clients", type=int, default=16)
    arguments = parser.parse_args()

    results, lock = [], threading.Lock()
    started = time.monotonic()
    deadline = started + arguments.seconds
    threads = [
        threading.Thread(target=client, args=(n, arguments.port, deadline, results, lock, started))
        for n in range(arguments.clients)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started

    latencies = sorted(l for _, ls, _, _, _, _ in results for l in ls)
    errors = sum(e for _, _, e, _, _, _ in results)
    reconnects = sum(r for _, _, _, r, _, _ in results)
    idle = sorted(n for n, ls, _, _, _, _ in results if not ls)
    first = next((f for _, _, _, _, f, _ in sorted(results) if f), None)

    print(
        f"http load  {len(latencies)} responses checked from {arguments.clients} clients in "
        f"{elapsed:.1f} s ({len(latencies) / elapsed:.1f}/s), {errors} error(s), "
        f"{reconnects} reconnect(s); latency p50 {percentile(latencies, 0.5) * 1000:.1f} ms, "
        f"p99 {percentile(latencies, 0.99) * 1000:.1f} ms, max "
        f"{(latencies[-1] if latencies else 0) * 1000:.1f} ms"
    )
    if first:
        print(f"http load  first error: {first}")
        # **When**, not only whether: a server that fails at one moment and
        # one that fails throughout are different faults.
        times = sorted(t for *_, ts in results for t in ts)
        print(
            f"http load  errors from {times[0]:.1f} s to {times[-1]:.1f} s into the run "
            f"(median {times[len(times) // 2]:.1f} s)"
        )
    if idle:
        print(f"http load  clients that completed nothing: {idle}")
    # **Every client must have been served**, not merely the total non-zero:
    # a server that answers one connection and starves fifteen is not serving
    # sixteen clients, and the gate says sixteen.
    return 0 if errors == 0 and latencies and not idle else 1


if __name__ == "__main__":
    sys.exit(main())

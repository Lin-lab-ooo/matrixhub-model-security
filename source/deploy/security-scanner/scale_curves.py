#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Summarize bounded public native_driver JSONL; never run a scanner.

CSV/JSON preserve every request, including failed/control requests. Optional
matplotlib plots show measured points only. No interpolation or accuracy claim.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re


MAX_RECEIPT = 32 << 20
FIELDS = ("receiptSha256", "mode", "manifestSha256", "provenance", "payloadPattern", "sourceSha256",
          "rulesInventorySha256", "generation", "nativeThreads", "batchFilesRequested", "batchIndex",
          "repetition", "files", "bytes", "meanFileBytes", "requestSeconds", "mibPerSecond",
          "httpStatus", "requestAssertionPassed", "completeCoverage", "expectedRejectionControl",
          "error", "driverPassed", "cleanupVerified", "cpuSecondsCgroup", "cpuSecondsWorker",
          "treeRssPeakBytesSampled", "cgroupMemoryPeakBytesLifetime", "deviceReadBytesCgroup",
          "deviceWriteBytesCgroup", "coldEngineStartupSeconds", "nativeWaveWidths", "nativeWaveBytes",
          "nativeWaveCompleted", "comparisonKey", "exploratoryFrontier")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def read_receipt(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_RECEIPT + 1)
    if len(raw) > MAX_RECEIPT:
        raise ValueError("receipt-byte-limit")
    records = []
    for line in raw.splitlines():
        if not line or len(line) > 65536:
            raise ValueError("receipt-line-limit")
        record = json.loads(line)
        if not isinstance(record, dict) or not isinstance(record.get("event"), str):
            raise ValueError("public-jsonl-required")
        records.append(record)
    return hashlib.sha256(raw).hexdigest(), records


def rows_from_receipt(path):
    digest, records = read_receipt(path)
    def one(event, required=False):
        values = [record for record in records if record["event"] == event]
        if len(values) > 1 or (required and not values):
            raise ValueError("one-driver-run-per-receipt-required")
        return values[0] if values else {}
    config, inputs = one("driverInputs", True), one("benchmarkInputs")
    receipt, ready = one("driverReceipt"), one("driverReady")
    mode = config.get("mode")
    if mode not in {"protocol", "phases"} or not isinstance(config.get("limits"), dict):
        raise ValueError("driver-context-required")
    if (config["limits"].get("native_threads") not in {1, 2, 4}
            or any(not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value)
                   for value in (config.get("sourceSha256"), config.get("rulesInventorySha256"), inputs.get("manifestSha256")))):
        raise ValueError("pinned-driver-context-required")
    other_limits = {key: value for key, value in config["limits"].items() if key != "native_threads"}
    comparison = {"manifestSha256": inputs.get("manifestSha256"), "sourceSha256": config.get("sourceSha256"),
                  "rulesInventorySha256": config.get("rulesInventorySha256"), "mode": mode,
                  "backend": config.get("backend"), "otherLimits": other_limits}
    rows = []
    for batch in records:
        if batch["event"] not in {"protocolBatch", "phaseBatch"}:
            continue
        if (batch["event"] == "protocolBatch") != (mode == "protocol"):
            raise ValueError("mixed-protocol-and-phase-receipt")
        files, size, elapsed = batch.get("files"), batch.get("bytes"), batch.get("wallSeconds")
        if type(files) is not int or files <= 0 or type(size) is not int or size < 0 or not numeric(elapsed) or elapsed == 0:
            raise ValueError("invalid-public-batch-size-or-time")
        summary = batch.get("summary") or {}
        rejection = summary.get("expectedRejectionControl") is True
        status = batch.get("httpStatus", 422 if batch.get("error") else 200)
        assertion = (summary.get("protocolValid") is True and summary.get("expectedKnown") == summary.get("expectedMatches") == files
                     and ((rejection and status == 422 and summary.get("completeCoverage") is False and batch.get("error") is not None)
                          or (not rejection and status == 200 and batch.get("error") is None)))
        complete = assertion and not rejection and all(outcome in {"clean", "block"} for outcome in summary.get("outcomes", [])) and len(summary.get("outcomes", [])) == files
        resources, phases = batch.get("resources") or {}, batch.get("phases") or {}
        counters, waves = resources.get("cgroupCounterDelta") or {}, phases.get("nativeWaveAttempts") or []
        generation = one("protocolConfiguration").get("bundle", {}).get("generation") if mode == "protocol" else one("phaseConfiguration").get("generation")
        if not isinstance(generation, str) or not re.fullmatch("[a-f0-9]{64}", generation):
            raise ValueError("generation-context-required")
        row = dict.fromkeys(FIELDS)
        row.update(receiptSha256=digest, mode=mode, manifestSha256=inputs.get("manifestSha256"),
                   provenance=inputs.get("provenance"), payloadPattern=inputs.get("payloadPattern", "upstream-or-unspecified"),
                   sourceSha256=config.get("sourceSha256"), rulesInventorySha256=config.get("rulesInventorySha256"), generation=generation,
                   nativeThreads=config["limits"].get("native_threads"), batchFilesRequested=batch.get("batchFilesRequested"),
                   batchIndex=batch.get("batchIndex"), repetition=batch.get("repetition"), files=files, bytes=size,
                   meanFileBytes=size / files, requestSeconds=elapsed, mibPerSecond=size / (1 << 20) / elapsed,
                   httpStatus=status, requestAssertionPassed=assertion, completeCoverage=complete, expectedRejectionControl=rejection,
                   error=batch.get("error"), driverPassed=receipt.get("passed") is True,
                   cleanupVerified=receipt.get("cleanupSuccess") is True and receipt.get("ownedProcessGroupsAbsent") is True and receipt.get("forcedKills") == 0,
                   cpuSecondsCgroup=counters.get("cpuUsageUsec") / 1e6 if numeric(counters.get("cpuUsageUsec")) else None,
                   cpuSecondsWorker=phases.get("workerCpuSeconds"), treeRssPeakBytesSampled=resources.get("treeRSSPeakBytesSampled"),
                   cgroupMemoryPeakBytesLifetime=resources.get("cgroupMemoryPeakBytesLifetime"),
                   deviceReadBytesCgroup=counters.get("ioReadBytes"), deviceWriteBytesCgroup=counters.get("ioWriteBytes"),
                   coldEngineStartupSeconds=ready.get("coldEngineStartupSeconds"),
                   nativeWaveWidths=[wave["selectedFiles"] for wave in waves], nativeWaveBytes=[wave["heldFdBytes"] for wave in waves],
                   nativeWaveCompleted=[wave["completed"] for wave in waves], comparisonKey=hashlib.sha256(canonical(comparison)).hexdigest(),
                   exploratoryFrontier=False)
        rows.append(row)
    return rows


def mark_frontier(rows):
    # Exploratory observations only: same input/source/rules/mode/other limits
    # and mean file size. No aggregation across unknown RSS/CPU measurements.
    candidates = [row for row in rows if row["completeCoverage"] and row["cleanupVerified"] and row["driverPassed"]
                  and numeric(row["cpuSecondsCgroup"]) and numeric(row["treeRssPeakBytesSampled"]) and row["bytes"] > 0]
    if len(candidates) > 4096:
        raise ValueError("bounded-frontier-point-limit")
    for row in candidates:
        def dominates(other):
            if (other["comparisonKey"], other["meanFileBytes"]) != (row["comparisonKey"], row["meanFileBytes"]) or other is row:
                return False
            a = (-other["mibPerSecond"], other["cpuSecondsCgroup"] / other["bytes"], other["treeRssPeakBytesSampled"])
            b = (-row["mibPerSecond"], row["cpuSecondsCgroup"] / row["bytes"], row["treeRssPeakBytesSampled"])
            return all(x <= y for x, y in zip(a, b)) and any(x < y for x, y in zip(a, b))
        row["exploratoryFrontier"] = not any(dominates(other) for other in candidates)


def plot(rows, destination):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5), constrained_layout=True)
    groups = {}
    for row in rows:
        key = (row["mode"], row["nativeThreads"], row["payloadPattern"], row["manifestSha256"])
        groups.setdefault(key, []).append(row)
    for index, (key, values) in enumerate(groups.items()):
        color = "C" + str(index % 10)
        label = f"{key[0]}, threads={key[1]}, {key[2]}, input={(key[3] or 'unknown')[:8]}"
        for row in values:
            good = row["completeCoverage"] and row["driverPassed"] and row["cleanupVerified"]
            marker = "o" if good else "x"
            x = row["bytes"] / (1 << 20)
            for axis, y in zip(axes, (row["requestSeconds"], row["mibPerSecond"],
                                      row["treeRssPeakBytesSampled"] / (1 << 20) if numeric(row["treeRssPeakBytesSampled"]) else None)):
                if y is not None:
                    axis.scatter(x, y, marker=marker, color=color, label=label)
        for axis in axes:
            axis.set_xlabel("Request bytes (MiB)")
            axis.grid(alpha=.2)
    for axis, title in zip(axes, ("Request time (s)", "Attempted bytes/time (MiB/s)", "Sampled process-tree peak RSS (MiB)")):
        axis.set_ylabel(title)
        handles, labels = axis.get_legend_handles_labels()
        unique = dict(zip(labels, handles))
        axis.legend(unique.values(), unique.keys(), fontsize=6)
    fig.suptitle("Measured requests: circles=verified complete; crosses=control/failure. No interpolation.")
    fig.savefig(destination, dpi=180)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipts", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True, help="new exact-owned output directory")
    parser.add_argument("--plot", action="store_true", help="requires preinstalled matplotlib; never installs dependencies")
    args = parser.parse_args()
    if len(args.receipts) > 256 or args.output.exists() or not args.output.parent.is_dir():
        parser.error("bounded receipt list and new output directory required")
    if sum(path.stat().st_size for path in args.receipts) > 64 << 20:
        parser.error("aggregate receipt byte limit")
    rows = [row for path in args.receipts for row in rows_from_receipt(path)]
    if not rows or len(rows) > 65536:
        parser.error("bounded nonempty measurements required")
    mark_frontier(rows)
    args.output.mkdir()
    with (args.output / "points.csv").open("x", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, FIELDS)
        writer.writeheader()
        writer.writerows({key: json.dumps(value) if isinstance(value, list) else value for key, value in row.items()} for row in rows)
    report = {"schemaVersion": 1, "points": rows, "notes": [
        "No scan or model loading performed by this summarizer; input receipt hashes retained.",
        "Mean file size is batch bytes/files and does not prove uniform file sizes.",
        "Failed/control attempted bytes/time is not completed scan throughput; crosses remain visible.",
        "Protocol and instrumented phase runs are separate; never add their timings.",
        "Cold engine is a new process; OS page/device caches were not cleared.",
        "Cgroup CPU/device I/O includes the harness; sampled RSS can miss peaks; lifetime memory peak is not per request.",
        "Exploratory frontier compares observed throughput/CPU per byte/RSS under matching recorded conditions; no causal or statistical guarantee.",
        "Controlled assertions, bytes and files are not malware accuracy, recall or application approval."]}
    (args.output / "points.json").write_bytes(canonical(report) + b"\n")
    if args.plot:
        plot(rows, args.output / "time-size-resources.png")
    print(json.dumps({"status": "PASS", "points": len(rows), "scannerExecuted": False, "plotGenerated": args.plot}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Dataset bootstrapper and benchmark harness for FlowSign.

This helper downloads reduced slices of popular intrusion-detection datasets
(UNSW-NB15, CIC-IDS2017, NSL-KDD), feeds any available PCAP captures through the
built snort3 binary (with FlowSign co-instantiated), and compares alerts against
supplied ground-truth labels to compute rudimentary precision/recall/F1.

The datasets are large, so only trimmed publicly-hosted CSV/PCAP slices are
fetched by default. If a file already exists locally, the download is skipped.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import re
import subprocess
import textwrap
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - fallback for minimal environments
    requests = None
    import urllib.error
    import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DEFAULT_SNORT_BIN = ROOT / "snort3" / "build" / "src" / "snort" / "snort"
DEFAULT_CONF = ROOT / "snort3" / "etc" / "snort.lua"


@dataclass
class DatasetFile:
    url: str
    path: pathlib.Path
    max_bytes: Optional[int] = None


@dataclass
class DatasetConfig:
    name: str
    files: List[DatasetFile]
    pcap_file: Optional[pathlib.Path]
    label_file: Optional[pathlib.Path]
    src_col: str = "srcip"
    dst_col: str = "dstip"
    sport_col: str = "sport"
    dport_col: str = "dsport"
    proto_col: str = "proto"
    label_col: str = "label"


DATASETS = {
    "unsw-nb15": DatasetConfig(
        name="UNSW-NB15",
        files=[
            DatasetFile(
                "https://raw.githubusercontent.com/defcom17/UNSW-NB15/master/UNSW_NB15_training-set.csv",
                DATA_DIR / "unsw-nb15" / "UNSW_NB15_training-set.csv",
                max_bytes=50_000_000,
            ),
            DatasetFile(
                "https://raw.githubusercontent.com/defcom17/UNSW-NB15/master/pcaps/UNSW-NB15-TESTING.pcap",
                DATA_DIR / "unsw-nb15" / "UNSW-NB15-TESTING.pcap",
                max_bytes=60_000_000,
            ),
        ],
        pcap_file=DATA_DIR / "unsw-nb15" / "UNSW-NB15-TESTING.pcap",
        label_file=DATA_DIR / "unsw-nb15" / "UNSW_NB15_training-set.csv",
        label_col="label",
    ),
    "cic-ids2017": DatasetConfig(
        name="CIC-IDS2017",
        files=[
            DatasetFile(
                "https://raw.githubusercontent.com/defcom17/CICIDS2017/master/TrafficLabelling/Friday-WorkingHours-Morning.pcap_ISCX.csv",
                DATA_DIR / "cic-ids2017" / "Friday-WorkingHours-Morning.pcap_ISCX.csv",
                max_bytes=40_000_000,
            ),
            DatasetFile(
                "https://raw.githubusercontent.com/defcom17/CICIDS2017/master/pcap/Friday-WorkingHours.pcap",
                DATA_DIR / "cic-ids2017" / "Friday-WorkingHours.pcap",
                max_bytes=60_000_000,
            ),
        ],
        pcap_file=DATA_DIR / "cic-ids2017" / "Friday-WorkingHours.pcap",
        label_file=DATA_DIR / "cic-ids2017" / "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        label_col="Label",
    ),
    "nsl-kdd": DatasetConfig(
        name="NSL-KDD",
        files=[
            DatasetFile(
                "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
                DATA_DIR / "nsl-kdd" / "KDDTest+.txt",
                max_bytes=10_000_000,
            )
        ],
        pcap_file=None,
        label_file=DATA_DIR / "nsl-kdd" / "KDDTest+.txt",
        src_col="srcip",
        dst_col="dstip",
        sport_col="sport",
        dport_col="dsport",
        proto_col="proto",
        label_col="label",
    ),
}


def download_file(file: DatasetFile) -> None:
    file.path.parent.mkdir(parents=True, exist_ok=True)
    if file.path.exists():
        print(f"[download] using cached {file.path}")
        return

    print(f"[download] fetching {file.url} -> {file.path}")
    total = 0
    if requests:
        stream = requests.get(file.url, stream=True, timeout=30)
        stream.raise_for_status()
        iterator = stream.iter_content(chunk_size=8192)
    else:
        stream = urllib.request.urlopen(file.url, timeout=30)  # nosec: B310
        iterator = iter(lambda: stream.read(8192), b"")

    with stream:
        with open(file.path, "wb") as handle:
            for chunk in iterator:
                if not chunk:
                    continue
                total += len(chunk)
                if file.max_bytes and total > file.max_bytes:
                    print(f"[download] truncating at {file.max_bytes} bytes to keep footprint small")
                    handle.write(chunk[: file.max_bytes - (total - len(chunk))])
                    break
                handle.write(chunk)
    print(f"[download] saved {file.path} ({file.path.stat().st_size} bytes)")


ALERT_REGEX = re.compile(r"(?P<src>\d+\.\d+\.\d+\.\d+):(?P<sport>\d+) -> (?P<dst>\d+\.\d+\.\d+\.\d+):(?P<dport>\d+)")


def parse_fastlog(path: pathlib.Path) -> List[Tuple[str, str, str, str]]:
    alerts: List[Tuple[str, str, str, str]] = []
    if not path.exists():
        return alerts
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = ALERT_REGEX.search(line)
            if match:
                alerts.append(
                    (
                        match.group("src"),
                        match.group("dst"),
                        match.group("sport"),
                        match.group("dport"),
                    )
                )
    return alerts


def parse_label_file(config: DatasetConfig) -> List[Tuple[str, str, str, str, str]]:
    if not config.label_file or not config.label_file.exists():
        return []

    labels: List[Tuple[str, str, str, str, str]] = []
    with open(config.label_file, "r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            src = row.get(config.src_col)
            dst = row.get(config.dst_col)
            sport = row.get(config.sport_col)
            dport = row.get(config.dport_col)
            label = row.get(config.label_col)
            if not (src and dst and sport and dport and label):
                continue
            labels.append((src, dst, sport, dport, label))
    return labels


def score_alerts(alerts: List[Tuple[str, str, str, str]], labels: List[Tuple[str, str, str, str, str]]) -> Tuple[int, int, int, int]:
    positives = {(src, dst, sport, dport) for src, dst, sport, dport, label in labels if label and label.lower() != "benign" and label.lower() != "normal"}
    negatives = {(src, dst, sport, dport) for src, dst, sport, dport, label in labels if label and label.lower() in {"benign", "normal"}}

    tp = sum(1 for alert in alerts if alert in positives)
    fp = sum(1 for alert in alerts if alert in negatives)
    fn = max(len(positives) - tp, 0)
    tn = max(len(negatives) - fp, 0)
    return tp, fp, fn, tn


def f1_score(tp: int, fp: int, fn: int) -> float:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def run_snort(pcap: pathlib.Path, snort_bin: pathlib.Path, config: pathlib.Path, output_dir: pathlib.Path) -> pathlib.Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    fastlog = output_dir / "fast.log"
    cmd = [
        str(snort_bin),
        "-c",
        str(config),
        "-r",
        str(pcap),
        "-A",
        "fast",
        "-l",
        str(output_dir),
    ]
    print(f"[snort] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    return fastlog


def benchmark_dataset(name: str, snort_bin: pathlib.Path, conf: pathlib.Path) -> None:
    if name not in DATASETS:
        raise SystemExit(f"Unknown dataset {name}. Choices: {', '.join(DATASETS)}")

    config = DATASETS[name]
    for file in config.files:
        download_file(file)

    if not config.pcap_file:
        print(f"[bench] {config.name} has no PCAP sample configured; skipping Snort replay")
        return

    fastlog = run_snort(config.pcap_file, snort_bin, conf, DATA_DIR / name / "snort-output")
    alerts = parse_fastlog(fastlog)
    labels = parse_label_file(config)
    tp, fp, fn, tn = score_alerts(alerts, labels)
    f1 = f1_score(tp, fp, fn)
    acc = (tp + tn) / max(tp + tn + fp + fn, 1)
    print(
        textwrap.dedent(
            f"""
            [bench] {config.name} results
                alerts: {len(alerts)}
                labels parsed: {len(labels)}
                TP={tp} FP={fp} FN={fn} TN={tn}
                accuracy={acc:.3f} f1={f1:.3f}
            """
        ).strip()
    )


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="FlowSign dataset bootstrapper")
    parser.add_argument("dataset", choices=DATASETS.keys(), help="Dataset to download and evaluate")
    parser.add_argument("--snort-bin", type=pathlib.Path, default=DEFAULT_SNORT_BIN, help="Path to snort binary")
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONF, help="Path to snort configuration")
    args = parser.parse_args(list(argv) if argv is not None else None)

    benchmark_dataset(args.dataset, args.snort_bin, args.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build a compact CVE velocity summary for a static dashboard."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

DATE_PATHS = (
    ("cveMetadata", "datePublished"),
    ("containers", "cna", "datePublished"),
    ("containers", "cna", "published"),
)

CNA_PATHS = (
    ("containers", "cna", "providerMetadata", "shortName"),
    ("cveMetadata", "assignerShortName"),
    ("cveMetadata", "assignerOrgId"),
)

CVE_ID_PATH = ("cveMetadata", "cveId")


@dataclass(slots=True)
class ParseStats:
    scanned_files: int = 0
    parsed_records: int = 0
    skipped_records: int = 0


def get_in(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def first_non_empty(data: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> Any:
    for path in paths:
        value = get_in(data, path)
        if value not in (None, ""):
            return value
    return None


def parse_record(raw: dict[str, Any]) -> dict[str, Any] | None:
    published_raw = first_non_empty(raw, DATE_PATHS)
    published = pd.to_datetime(published_raw, utc=True, errors="coerce")
    if pd.isna(published):
        return None

    cna = first_non_empty(raw, CNA_PATHS) or "UNKNOWN"
    cve_id = get_in(raw, CVE_ID_PATH) or "UNKNOWN"
    return {
        "published_at": published,
        "published_second": published.floor("s"),
        "cna": str(cna),
        "cve_id": str(cve_id),
    }


def collect_rows(cvelist_path: Path) -> tuple[list[dict[str, Any]], ParseStats]:
    stats = ParseStats()
    rows: list[dict[str, Any]] = []

    for json_file in sorted(cvelist_path.rglob("CVE-*.json")):
        stats.scanned_files += 1
        try:
            raw = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            stats.skipped_records += 1
            continue

        row = parse_record(raw)
        if row is None:
            stats.skipped_records += 1
            continue

        rows.append(row)
        stats.parsed_records += 1

    return rows, stats


def seconds_per_cve(events: pd.Series, window_days: int) -> float | None:
    if events.empty:
        return None

    end = events.max()
    start = end - pd.Timedelta(days=window_days)
    count = int(events[(events >= start) & (events <= end)].shape[0])
    if count <= 0:
        return None

    window_seconds = window_days * 24 * 60 * 60
    return float(window_seconds / count)


def format_heartbeat(seconds_value: float | None) -> str:
    if seconds_value is None:
        return "N/A"

    total = int(round(seconds_value))
    minutes, seconds = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def global_trend(df: pd.DataFrame) -> list[dict[str, Any]]:
    unique_events = (
        df[["published_second"]]
        .drop_duplicates()
        .sort_values("published_second")
        .set_index("published_second")
    )

    deltas = unique_events.index.to_series().diff().dt.total_seconds().dropna()
    if deltas.empty:
        return []

    monthly = deltas.resample("MS").agg(["mean", "median", "count"]).dropna()
    return [
        {
            "date": idx.strftime("%Y-%m-%d"),
            "avgIntervalSeconds": float(row["mean"]),
            "medianIntervalSeconds": float(row["median"]),
            "eventCount": int(row["count"]),
        }
        for idx, row in monthly.iterrows()
    ]


def cna_rollups(df: pd.DataFrame, min_events: int = 20) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    leaderboard: list[dict[str, Any]] = []
    trend_by_cna: dict[str, list[dict[str, Any]]] = {}

    for cna, group in df.groupby("cna"):
        unique_seconds = group["published_second"].drop_duplicates().sort_values()
        if unique_seconds.shape[0] < min_events:
            continue

        sec_30 = seconds_per_cve(unique_seconds, 30)
        sec_90 = seconds_per_cve(unique_seconds, 90)
        if sec_30 is None and sec_90 is None:
            continue

        leaderboard.append(
            {
                "cna": cna,
                "window30SecondsPerCve": sec_30,
                "window90SecondsPerCve": sec_90,
                "recentEvents30d": int(
                    unique_seconds[
                        unique_seconds >= (unique_seconds.max() - pd.Timedelta(days=30))
                    ].shape[0]
                ),
                "totalEvents": int(unique_seconds.shape[0]),
            }
        )

        deltas = unique_seconds.diff().dt.total_seconds().dropna()
        monthly = deltas.resample("MS").agg(["mean", "median", "count"]).dropna()
        trend_by_cna[cna] = [
            {
                "date": idx.strftime("%Y-%m-%d"),
                "avgIntervalSeconds": float(row["mean"]),
                "medianIntervalSeconds": float(row["median"]),
                "eventCount": int(row["count"]),
            }
            for idx, row in monthly.iterrows()
        ]

    leaderboard.sort(
        key=lambda item: item["window30SecondsPerCve"]
        if item["window30SecondsPerCve"] is not None
        else float("inf")
    )
    return leaderboard[:200], trend_by_cna


def build_summary(cvelist_path: Path) -> dict[str, Any]:
    rows, stats = collect_rows(cvelist_path)
    if not rows:
        raise RuntimeError("No valid CVE records were parsed.")

    df = pd.DataFrame(rows).sort_values("published_at")
    global_seconds = df["published_second"].drop_duplicates().sort_values()

    sec_30 = seconds_per_cve(global_seconds, 30)
    sec_90 = seconds_per_cve(global_seconds, 90)
    leaderboard, trend_by_cna = cna_rollups(df)

    return {
        "generatedAt": datetime.now(tz=UTC).isoformat(),
        "sourcePath": str(cvelist_path),
        "stats": {
            "scannedFiles": stats.scanned_files,
            "parsedRecords": stats.parsed_records,
            "skippedRecords": stats.skipped_records,
            "distinctCnas": int(df["cna"].nunique()),
        },
        "global": {
            "heartbeat": {
                "windowDays": 30,
                "secondsPerCve": sec_30,
                "display": format_heartbeat(sec_30),
            },
            "rolling": {
                "window30SecondsPerCve": sec_30,
                "window90SecondsPerCve": sec_90,
            },
            "trend": global_trend(df),
        },
        "cna": {
            "leaderboard": leaderboard,
            "trendByCna": trend_by_cna,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build CVE velocity summary JSON")
    parser.add_argument(
        "--cvelist-path",
        type=Path,
        required=True,
        help="Path to the local cvelistV5 checkout.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/assets/data/summary.json"),
        help="Output JSON path.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = build_summary(args.cvelist_path)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote summary to {args.output}")


if __name__ == "__main__":
    main()

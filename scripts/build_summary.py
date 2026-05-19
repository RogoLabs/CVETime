#!/usr/bin/env python3
"""Build a compact CVE velocity summary for a static dashboard."""

from __future__ import annotations

import argparse
import json
import re
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

SEVERITY_ORDER = {
  "NONE": 0,
  "LOW": 1,
  "MEDIUM": 2,
  "HIGH": 3,
  "CRITICAL": 4,
}


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


def deep_find_first(data: Any, key_names: set[str]) -> Any:
  if isinstance(data, dict):
    for key, value in data.items():
      if key in key_names and value not in (None, ""):
        return value
      found = deep_find_first(value, key_names)
      if found not in (None, ""):
        return found
  elif isinstance(data, list):
    for item in data:
      found = deep_find_first(item, key_names)
      if found not in (None, ""):
        return found
  return None


def normalize_severity_label(label: Any, score: Any = None) -> str | None:
  if label not in (None, ""):
    normalized = str(label).strip().upper().replace("_", " ")
    normalized = normalized.replace(" ", " ")
    if normalized in SEVERITY_ORDER:
      return normalized
    return normalized

  if score is None:
    return None

  try:
    numeric_score = float(score)
  except (TypeError, ValueError):
    return None

  if numeric_score >= 9.0:
    return "CRITICAL"
  if numeric_score >= 7.0:
    return "HIGH"
  if numeric_score >= 4.0:
    return "MEDIUM"
  if numeric_score > 0.0:
    return "LOW"
  return "NONE"


def extract_severity_details(raw: dict[str, Any]) -> dict[str, Any]:
  severity_label = deep_find_first(raw, {"severity", "baseSeverity"})
  severity_score = deep_find_first(raw, {"baseScore", "score"})
  severity_vector = deep_find_first(raw, {"vectorString"})

  normalized_label = normalize_severity_label(severity_label, severity_score)
  if normalized_label is None and severity_score is None and severity_vector is None:
    return {}

  details: dict[str, Any] = {}
  if normalized_label is not None:
    details["label"] = normalized_label
    details["order"] = SEVERITY_ORDER.get(normalized_label, -1)
  if severity_score is not None:
    try:
      details["score"] = float(severity_score)
    except (TypeError, ValueError):
      pass
  if severity_vector not in (None, ""):
    details["vector"] = str(severity_vector)
  return details


def parse_record(raw: dict[str, Any]) -> dict[str, Any] | None:
    published_raw = first_non_empty(raw, DATE_PATHS)
    published = pd.to_datetime(published_raw, utc=True, errors="coerce")
    if pd.isna(published):
        return None

    cna = first_non_empty(raw, CNA_PATHS) or "UNKNOWN"
    cve_id = get_in(raw, CVE_ID_PATH) or "UNKNOWN"
    severity = extract_severity_details(raw)
    return {
        "published_at": published,
        "published_second": published.floor("s"),
        "cna": str(cna),
        "cve_id": str(cve_id),
      "severity_label": severity.get("label"),
      "severity_score": severity.get("score"),
      "severity_order": severity.get("order"),
      "severity_vector": severity.get("vector"),
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


def monthly_deltas(timestamps: pd.Series) -> pd.Series:
    timeline = pd.Series(pd.to_datetime(timestamps, utc=True), copy=False).drop_duplicates().sort_values()
    if timeline.shape[0] < 2:
        return pd.Series(dtype="float64")

    indexed_timeline = pd.Series(timeline.values, index=pd.DatetimeIndex(timeline.values))
    return indexed_timeline.diff().dt.total_seconds().dropna()


def quantile_seconds(values: pd.Series, quantile: float) -> float | None:
  if values.empty:
    return None
  try:
    return float(values.quantile(quantile))
  except Exception:
    return None


def consistency_grade(score: float) -> str:
  if score >= 90:
    return "A"
  if score >= 80:
    return "B"
  if score >= 70:
    return "C"
  if score >= 60:
    return "D"
  return "F"


def robust_consistency_score(values: pd.Series) -> dict[str, Any]:
  if values.empty:
    return {
      "score": None,
      "grade": "N/A",
      "medianSeconds": None,
      "p90Seconds": None,
      "trimmedCount": 0,
    }

  q05 = quantile_seconds(values, 0.05)
  q25 = quantile_seconds(values, 0.25)
  q50 = quantile_seconds(values, 0.50)
  q75 = quantile_seconds(values, 0.75)
  q90 = quantile_seconds(values, 0.90)
  q95 = quantile_seconds(values, 0.95)

  trimmed = values
  if q05 is not None and q95 is not None:
    trimmed = values[(values >= q05) & (values <= q95)]
  if trimmed.empty:
    trimmed = values

  trimmed_mean = float(trimmed.mean()) if not trimmed.empty else None
  trimmed_std = float(trimmed.std(ddof=0)) if trimmed.shape[0] > 1 else 0.0
  coefficient = (trimmed_std / trimmed_mean) if trimmed_mean not in (None, 0) else 0.0
  spread_penalty = 0.0
  if q25 is not None and q75 is not None and q50 not in (None, 0):
    spread_penalty = max(0.0, ((q75 - q25) / q50) * 25.0)

  score = max(0.0, 100.0 - min(100.0, (coefficient * 65.0) + spread_penalty))
  score = round(score)

  return {
    "score": score,
    "grade": consistency_grade(score),
    "medianSeconds": q50,
    "p90Seconds": q90,
    "trimmedCount": int(trimmed.shape[0]),
  }


def monthly_percentile_trend(timestamps: pd.Series) -> list[dict[str, Any]]:
  deltas = monthly_deltas(timestamps)
  if deltas.empty:
    return []

  monthly = deltas.resample("MS").agg(
    p50=lambda x: float(x.quantile(0.50)),
    p90=lambda x: float(x.quantile(0.90)),
    count="count",
  ).dropna()

  return [
    {
      "date": idx.strftime("%Y-%m-%d"),
      "p50IntervalSeconds": float(row["p50"]),
      "p90IntervalSeconds": float(row["p90"]),
      "eventCount": int(row["count"]),
    }
    for idx, row in monthly.iterrows()
  ]


def severity_profile(group: pd.DataFrame) -> dict[str, Any]:
  ordered = group.sort_values(["published_second", "cve_id"]).drop_duplicates(subset=["published_second"])
  if ordered.shape[0] < 2:
    return {"summary": {}, "points": []}

  interval_seconds = ordered["published_second"].diff().dt.total_seconds()
  severity_summary: dict[str, dict[str, Any]] = {}
  severity_points: list[dict[str, Any]] = []

  for idx in range(1, ordered.shape[0]):
    interval_value = interval_seconds.iloc[idx]
    if pd.isna(interval_value):
      continue

    row = ordered.iloc[idx]
    label = row.get("severity_label")
    if label in (None, "", "UNKNOWN"):
      continue

    label_key = str(label).upper()
    bucket = severity_summary.setdefault(label_key, {"count": 0, "values": []})
    bucket["count"] += 1
    bucket["values"].append(float(interval_value))
    severity_points.append(
      {
        "date": row["published_second"].strftime("%Y-%m-%d"),
        "cveId": row["cve_id"],
        "severity": label_key,
        "severityValue": SEVERITY_ORDER.get(label_key, -1),
        "timeToPublishSeconds": float(interval_value),
      }
    )

  for label_key, bucket in severity_summary.items():
    values = pd.Series(bucket.pop("values"), dtype="float64")
    bucket["medianSeconds"] = quantile_seconds(values, 0.50)
    bucket["p90Seconds"] = quantile_seconds(values, 0.90)

  return {"summary": severity_summary, "points": severity_points}


def global_trend(df: pd.DataFrame) -> list[dict[str, Any]]:
    unique_events = (
        df[["published_second"]]
        .drop_duplicates()
        .sort_values("published_second")
        .set_index("published_second")
    )

    deltas = monthly_deltas(unique_events.index.to_series())
    if deltas.empty:
        return []

    monthly = deltas.resample("MS").agg(
        mean="mean",
        median="median",
        count="count",
        p25=lambda x: float(x.quantile(0.25)),
        p75=lambda x: float(x.quantile(0.75)),
    ).dropna()
    return [
        {
            "date": idx.strftime("%Y-%m-%d"),
            "avgIntervalSeconds": float(row["mean"]),
            "medianIntervalSeconds": float(row["median"]),
            "p25IntervalSeconds": float(row["p25"]),
            "p75IntervalSeconds": float(row["p75"]),
            "eventCount": int(row["count"]),
        }
        for idx, row in monthly.iterrows()
    ]


def to_slug(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name.lower())
    slug = re.sub(r"[\s_]+", "-", slug)
    return slug.strip("-")


def cna_rollups(df: pd.DataFrame, min_events: int = 20) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
  leaderboard: list[dict[str, Any]] = []
  shard_exports: dict[str, dict[str, Any]] = {}

  for cna, group in df.groupby("cna"):
    ordered = group.sort_values(["published_second", "cve_id"]).drop_duplicates(subset=["published_second"])
    unique_seconds = ordered["published_second"]
    if unique_seconds.shape[0] < min_events:
      continue

    sec_30 = seconds_per_cve(unique_seconds, 30)
    sec_90 = seconds_per_cve(unique_seconds, 90)
    if sec_30 is None and sec_90 is None:
      continue

    deltas = monthly_deltas(unique_seconds)
    trend = monthly_percentile_trend(unique_seconds)
    consistency = robust_consistency_score(deltas)
    severity = severity_profile(ordered)
    slug = to_slug(str(cna))

    leaderboard.append(
      {
        "cna": cna,
        "slug": slug,
        "rank": 0,
        "window30SecondsPerCve": sec_30,
        "totalEvents": int(unique_seconds.shape[0]),
      }
    )

    shard_exports[slug] = {
      "generatedAt": datetime.now(tz=UTC).isoformat(),
      "cna": {
        "name": str(cna),
        "slug": slug,
        "rank": 0,
        "window30SecondsPerCve": sec_30,
        "window90SecondsPerCve": sec_90,
        "totalEvents": int(unique_seconds.shape[0]),
        "consistencyScore": consistency["score"],
        "consistencyGrade": consistency["grade"],
        "consistencyMedianSeconds": consistency["medianSeconds"],
        "consistencyP90Seconds": consistency["p90Seconds"],
        "percentileFaster": 0,
      },
      "trend": trend,
      "metrics": {
        "p50Seconds": consistency["medianSeconds"],
        "p90Seconds": consistency["p90Seconds"],
        "trimmedCount": consistency["trimmedCount"],
      },
      "severity": severity,
      "peers": [],
    }

    leaderboard.sort(
        key=lambda item: item["window30SecondsPerCve"]
        if item["window30SecondsPerCve"] is not None
        else float("inf")
    )

    # Assign ranks and percentiles now that list is sorted
    total = len(leaderboard)
    for rank, item in enumerate(leaderboard, start=1):
        item["rank"] = rank
        item["percentileFaster"] = round((1 - (rank - 1) / max(total - 1, 1)) * 100) if total > 1 else 100

    for item in leaderboard:
        shard = shard_exports.get(item["slug"])
        if shard is None:
            continue
        shard["cna"]["rank"] = item["rank"]
        shard["cna"]["percentileFaster"] = item["percentileFaster"]
        shard["peers"] = leaderboard[:20]

  return leaderboard[:200], shard_exports


def build_summary(cvelist_path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
  rows, stats = collect_rows(cvelist_path)
  if not rows:
    raise RuntimeError("No valid CVE records were parsed.")

  df = pd.DataFrame(rows).sort_values("published_at")
  global_seconds = df["published_second"].drop_duplicates().sort_values()

  sec_30 = seconds_per_cve(global_seconds, 30)
  sec_90 = seconds_per_cve(global_seconds, 90)
  leaderboard, shard_exports = cna_rollups(df)

  summary = {
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
    },
  }

  return summary, shard_exports


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
    parser.add_argument(
        "--cna-pages-dir",
        type=Path,
        default=None,
        help="If set, generate per-CNA static data files under this directory.",
    )
    return parser.parse_args()


CNA_TEMPLATE = """\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{cna_name} · CVETime</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {{
        darkMode: 'class',
        theme: {{
          extend: {{
            colors: {{
              ink: {{ DEFAULT: "#06101d", light: "#f8fafc" }},
              panel: {{ DEFAULT: "#10233c", light: "#f1f5f9" }},
              accent: {{ DEFAULT: "#2ee6ff", light: "#0ea5e9" }},
              accent2: {{ DEFAULT: "#2dd4bf", light: "#14b8a6" }},
              accent3: {{ DEFAULT: "#60a5fa", light: "#6366f1" }}
            }},
            fontFamily: {{ display: ["Space Grotesk", "ui-sans-serif", "system-ui"] }}
          }}
        }}
      }};
    </script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="canonical" href="/cna/{slug}/" />
  </head>
  <body class="bg-ink-light text-slate-900 dark:bg-ink dark:text-slate-100 min-h-screen transition-colors duration-300">
    <div class="fixed inset-0 -z-20 bg-[radial-gradient(circle_at_15%_15%,rgba(14,165,233,0.14),transparent_30%),radial-gradient(circle_at_80%_0%,rgba(99,102,241,0.12),transparent_26%),radial-gradient(circle_at_90%_90%,rgba(20,184,166,0.10),transparent_22%),linear-gradient(180deg,#f8fbff_0%,#eff6ff_48%,#e0f2fe_100%)] dark:bg-[radial-gradient(circle_at_15%_15%,rgba(46,230,255,0.15),transparent_28%),radial-gradient(circle_at_80%_0%,rgba(96,165,250,0.15),transparent_26%),radial-gradient(circle_at_90%_90%,rgba(45,212,191,0.10),transparent_22%),linear-gradient(180deg,#040a13_0%,#081321_48%,#06101d_100%)]"></div>
    <div class="fixed inset-0 -z-10 opacity-40 dark:opacity-30 bg-[linear-gradient(rgba(14,165,233,0.07)_1px,transparent_1px),linear-gradient(90deg,rgba(14,165,233,0.07)_1px,transparent_1px)] dark:bg-[linear-gradient(rgba(148,163,184,0.07)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.07)_1px,transparent_1px)] bg-[size:88px_88px]"></div>
    <script>
      (function() {{
        const saved = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (saved === 'dark' || (!saved && prefersDark)) document.documentElement.classList.add('dark');
      }})();
    </script>

    <header class="sticky top-0 z-20 border-b border-sky-200/80 dark:border-white/10 bg-[rgba(248,250,252,0.78)] dark:bg-slate-950/90 backdrop-blur-xl">
      <div class="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
        <a href="../../" class="text-xs text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-cyan-400 transition-colors">← Global Dashboard</a>
        <span class="text-slate-400 dark:text-slate-600">/</span>
        <a href="../" class="text-xs text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-cyan-400 transition-colors">CNA Directory</a>
        <span class="text-slate-400 dark:text-slate-600">/</span>
        <span class="text-xs text-slate-900 dark:text-slate-200">{cna_name}</span>
        <div class="ml-auto">
          <button id="themeToggle" class="px-2 py-1 rounded bg-white/70 dark:bg-white/5 border border-sky-200/80 dark:border-white/10 text-xs text-slate-700 dark:text-slate-300 hover:bg-sky-100 dark:hover:bg-cyan-400/10 transition-colors">
            <span id="themeIcon">🌙</span> Theme
          </button>
        </div>
      </div>
    </header>

    <main class="max-w-6xl mx-auto px-4 py-8">
      <div class="mb-8">
        <p class="text-xs uppercase tracking-widest text-sky-700 dark:text-cyan-400 mb-2">CNA Profile</p>
        <h1 class="text-3xl md:text-4xl font-semibold text-slate-950 dark:text-white">{cna_name}</h1>
        <p class="text-slate-600 dark:text-slate-400 mt-1 text-sm">Percentile distribution, consistency, and backlog severity signals</p>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8">
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">30d Heartbeat</p>
          <p id="hero30d" class="text-2xl font-semibold text-accent-light dark:text-cyan-400 mt-1">--</p>
        </div>
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">Consistency</p>
          <p id="heroConsistency" class="text-2xl font-semibold text-sky-700 dark:text-sky-400 mt-1">--</p>
        </div>
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">P50 / P90</p>
          <p id="heroPercentiles" class="text-2xl font-semibold text-accent2-light dark:text-teal-400 mt-1">--</p>
        </div>
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">Total CVEs</p>
          <p id="heroTotal" class="text-2xl font-semibold text-indigo-600 dark:text-indigo-400 mt-1">--</p>
        </div>
      </div>

      <section class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 p-4 md:p-6 mb-8 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none">
        <div class="flex items-center justify-between gap-3 mb-4 flex-wrap">
          <div>
            <h2 class="text-lg font-semibold text-slate-950 dark:text-white">Percentile Distribution</h2>
            <p class="text-xs text-slate-500 dark:text-slate-400">P50 versus P90 to expose backlog tail behavior</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap justify-end">
            <label for="rangeToggle" class="text-xs text-slate-600 dark:text-slate-300">Range:</label>
            <select id="rangeToggle" class="bg-white/80 dark:bg-slate-900 border border-sky-200/80 dark:border-white/10 rounded px-2 py-1 text-xs text-slate-900 dark:text-slate-100">
              <option value="24m" selected>24 months</option>
              <option value="recent">2017+</option>
              <option value="all">All history</option>
            </select>
            <label for="scaleToggle" class="text-xs text-slate-600 dark:text-slate-300">Y Scale:</label>
            <select id="scaleToggle" class="bg-white/80 dark:bg-slate-900 border border-sky-200/80 dark:border-white/10 rounded px-2 py-1 text-xs text-slate-900 dark:text-slate-100">
              <option value="linear" selected>Linear</option>
              <option value="logarithmic">Logarithmic</option>
            </select>
          </div>
        </div>
        <div class="h-72 md:h-80">
          <canvas id="cnaChart"></canvas>
        </div>
      </section>

      <section id="severitySection" class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 p-4 md:p-6 mb-8 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none hidden">
        <div class="mb-4">
          <h2 class="text-lg font-semibold text-slate-950 dark:text-white">Time to Publish vs Severity</h2>
          <p class="text-xs text-slate-500 dark:text-slate-400">Scatter plot only appears when severity metadata is available</p>
        </div>
        <div class="h-72 md:h-80">
          <canvas id="severityChart"></canvas>
        </div>
      </section>

      <section class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 p-4 md:p-6 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none">
        <div class="flex items-center justify-between gap-3 mb-4 flex-wrap">
          <div>
            <h2 class="text-lg font-semibold text-slate-950 dark:text-white">Peer Snapshot</h2>
            <p class="text-xs text-slate-500 dark:text-slate-400">Top CNA leaderboard context from the global summary</p>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-slate-500 dark:text-slate-400 border-b border-sky-200/80 dark:border-white/10 text-xs uppercase tracking-wider">
                <th class="py-2 pr-3">Rank</th>
                <th class="py-2 pr-3">CNA</th>
                <th class="py-2 pr-3">30d Interval</th>
                <th class="py-2">Total CVEs</th>
              </tr>
            </thead>
            <tbody id="peerTable"></tbody>
          </table>
        </div>
      </section>
    </main>

    <script>
      const SHARD_PATH = "../../assets/data/cna/{slug}.json";
      const SUMMARY_PATH = "../../assets/data/summary.json";

      function fmtNumber(v) {{
        if (v == null || isNaN(v)) return "--";
        return new Intl.NumberFormat().format(v);
      }}

      function formatDuration(seconds) {{
        if (seconds == null || isNaN(seconds)) return "--";
        seconds = Math.round(seconds);
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;
        const out = [];
        if (d > 0) out.push(d + "d");
        if (h > 0) out.push(h + "h");
        if (m > 0) out.push(m + "m");
        if (s > 0 || out.length === 0) out.push(s + "s");
        return out.join(" ");
      }}

      function themeIsDark() {{
        return document.documentElement.classList.contains("dark");
      }}

      function setTheme(mode) {{
        const icon = document.getElementById("themeIcon");
        if (mode === "dark") {{
          document.documentElement.classList.add("dark");
          icon.textContent = "🌙";
          localStorage.setItem("theme", "dark");
        }} else {{
          document.documentElement.classList.remove("dark");
          icon.textContent = "☀️";
          localStorage.setItem("theme", "light");
        }}
      }}

      function getTrendPoints(trend, range) {{
        if (range === "all") return trend;
        if (range === "24m") {{
          const now = new Date();
          const twentyFourMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 24, 1);
          const cutoffDate = twentyFourMonthsAgo.toISOString().split('T')[0];
          return trend.filter(point => point.date >= cutoffDate);
        }}
        return trend.filter(point => point.date >= "2017-01-01");
      }}

      function gradeColor(grade) {{
        const map = {{ A: "#14b8a6", B: "#0ea5e9", C: "#6366f1", D: "#f59e0b", F: "#ef4444" }};
        return map[grade] || "#0ea5e9";
      }}

      function renderPercentileChart(trend, scale, range) {{
        const ctx = document.getElementById("cnaChart").getContext("2d");
        if (window._cnaChart) window._cnaChart.destroy();

        const points = getTrendPoints(trend, range);
        const labels = points.map(point => point.date);
        const p50 = points.map(point => point.p50IntervalSeconds);
        const p90 = points.map(point => point.p90IntervalSeconds);
        const dark = themeIsDark();

        window._cnaChart = new Chart(ctx, {{
          type: "line",
          data: {{
            labels,
            datasets: [
              {{
                label: "P90",
                data: p90,
                fill: "+1",
                borderColor: "transparent",
                backgroundColor: dark ? "rgba(46,230,255,0.10)" : "rgba(14,165,233,0.10)",
                pointRadius: 0,
                tension: 0.25,
                order: 2
              }},
              {{
                label: "P50",
                data: p50,
                borderColor: dark ? "rgba(46,230,255,0.95)" : "#0ea5e9",
                backgroundColor: "transparent",
                pointRadius: 2,
                pointHoverRadius: 5,
                borderWidth: 2.5,
                tension: 0.25,
                order: 1
              }}
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            interaction: {{ mode: "index", intersect: false }},
            plugins: {{
              legend: {{ display: true, labels: {{ color: dark ? "#dbeafe" : "#334155" }} }},
              tooltip: {{
                backgroundColor: dark ? "rgba(6,16,29,0.96)" : "#f1f5f9",
                titleColor: dark ? "#f8fafc" : "#0f172a",
                bodyColor: dark ? "#dbeafe" : "#334155",
                callbacks: {{
                  label: function(ctx) {{
                    return ctx.dataset.label + ": " + formatDuration(ctx.parsed.y);
                  }}
                }}
              }}
            }},
            scales: {{
              x: {{ ticks: {{ color: dark ? "#94a3b8" : "#64748b" }}, grid: {{ color: dark ? "rgba(148,163,184,0.10)" : "rgba(100,116,139,0.08)" }} }},
              y: {{
                type: scale,
                min: scale === "logarithmic" ? undefined : 0,
                ticks: {{ color: dark ? "#94a3b8" : "#64748b", callback: value => formatDuration(value) }},
                grid: {{ color: dark ? "rgba(148,163,184,0.10)" : "rgba(100,116,139,0.08)" }},
                title: {{ display: true, text: "Time to Publish", color: dark ? "#94a3b8" : "#64748b" }}
              }}
            }}
          }}
        }});
      }}

      function renderSeverityChart(points) {{
        if (!points || points.length === 0) return;
        const section = document.getElementById("severitySection");
        section.classList.remove("hidden");

        const ctx = document.getElementById("severityChart").getContext("2d");
        if (window._severityChart) window._severityChart.destroy();

        const severityLabels = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
        const dark = themeIsDark();

        window._severityChart = new Chart(ctx, {{
          type: "scatter",
          data: {{
            datasets: [{{
              label: "Time to Publish vs Severity",
              data: points.map(point => ({{
                x: point.timeToPublishSeconds,
                y: point.severityValue,
                severity: point.severity,
                cveId: point.cveId,
              }})),
              backgroundColor: dark ? "rgba(46,230,255,0.65)" : "rgba(14,165,233,0.65)",
              borderColor: dark ? "rgba(46,230,255,0.95)" : "#0ea5e9",
              pointRadius: 4,
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{
                backgroundColor: dark ? "rgba(6,16,29,0.96)" : "#f1f5f9",
                titleColor: dark ? "#f8fafc" : "#0f172a",
                bodyColor: dark ? "#dbeafe" : "#334155",
                callbacks: {{
                  label: function(ctx) {{
                    const label = ctx.raw.severity || "UNKNOWN";
                    return label + ": " + formatDuration(ctx.parsed.x);
                  }}
                }}
              }}
            }},
            scales: {{
              x: {{
                type: "linear",
                ticks: {{ color: dark ? "#94a3b8" : "#64748b", callback: value => formatDuration(value) }},
                grid: {{ color: dark ? "rgba(148,163,184,0.10)" : "rgba(100,116,139,0.08)" }},
                title: {{ display: true, text: "Time to Publish", color: dark ? "#94a3b8" : "#64748b" }}
              }},
              y: {{
                min: 0,
                max: 4,
                ticks: {{
                  color: dark ? "#94a3b8" : "#64748b",
                  stepSize: 1,
                  callback: value => severityLabels[value] || ""
                }},
                grid: {{ color: dark ? "rgba(148,163,184,0.10)" : "rgba(100,116,139,0.08)" }},
                title: {{ display: true, text: "Severity", color: dark ? "#94a3b8" : "#64748b" }}
              }}
            }}
          }}
        }});
      }}

      async function boot() {{
        const saved = localStorage.getItem("theme");
        const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        setTheme(saved || (prefersDark ? "dark" : "light"));

        const themeToggle = document.getElementById("themeToggle");
        themeToggle.addEventListener("click", () => {{
          setTheme(themeIsDark() ? "light" : "dark");
          if (window._cnaChart) renderPercentileChart(window._shard.trend || [], document.getElementById("scaleToggle").value, document.getElementById("rangeToggle").value);
          if (window._severityChart && window._shard.severity && window._shard.severity.points.length) renderSeverityChart(window._shard.severity.points);
        }});

        const response = await fetch(SHARD_PATH, {{ cache: "no-store" }});
        if (!response.ok) throw new Error(`Failed to fetch shard: ${{response.status}}`);
        const shard = await response.json();
        window._shard = shard;

        const cna = shard.cna || {{}};
        document.getElementById("hero30d").textContent = formatDuration(cna.window30SecondsPerCve);
        document.getElementById("heroConsistency").textContent = (cna.consistencyGrade || "--") + (cna.consistencyScore != null ? ` / ${{cna.consistencyScore}}` : "");
        document.getElementById("heroPercentiles").textContent = `${{formatDuration(shard.metrics?.p50Seconds)}} / ${{formatDuration(shard.metrics?.p90Seconds)}}`;
        document.getElementById("heroTotal").textContent = fmtNumber(cna.totalEvents);

        const trend = shard.trend || [];
        renderPercentileChart(trend, document.getElementById("scaleToggle").value, document.getElementById("rangeToggle").value);

        document.getElementById("rangeToggle").addEventListener("change", e => {{
          renderPercentileChart(trend, document.getElementById("scaleToggle").value, e.target.value);
        }});

        document.getElementById("scaleToggle").addEventListener("change", e => {{
          renderPercentileChart(trend, e.target.value, document.getElementById("rangeToggle").value);
        }});

        if (shard.severity && shard.severity.points && shard.severity.points.length) {{
          renderSeverityChart(shard.severity.points);
        }}

        const tbody = document.getElementById("peerTable");
        (shard.peers || []).slice(0, 20).forEach(row => {{
          const isCurrent = row.slug === "{slug}";
          const tr = document.createElement("tr");
          tr.className = "border-b border-sky-200/70 dark:border-white/5 " + (isCurrent ? "bg-sky-100/90 dark:bg-cyan-400/10 font-semibold" : "hover:bg-sky-100/70 dark:hover:bg-white/5") + " transition-colors";
          const cnaCell = isCurrent
            ? '<span class="text-sky-700 dark:text-cyan-300">' + row.cna + '</span>'
            : '<a href="../' + row.slug + '/" class="text-slate-900 dark:text-slate-200 hover:text-sky-600 dark:hover:text-cyan-300 transition-colors">' + row.cna + '</a>';
          tr.innerHTML = `
            <td class="py-2 pr-3 text-slate-500 dark:text-slate-400">${{row.rank ?? '--'}}</td>
            <td class="py-2 pr-3">${{cnaCell}}</td>
            <td class="py-2 pr-3 text-sky-700 dark:text-cyan-200">${{formatDuration(row.window30SecondsPerCve)}}</td>
            <td class="py-2 text-slate-700 dark:text-slate-300">${{fmtNumber(row.totalEvents)}}</td>
          `;
          tbody.appendChild(tr);
        }});
      }}

      boot().catch(console.error);
    </script>
  </body>
</html>
"""


def generate_cna_pages(summary: dict[str, Any], shard_exports: dict[str, dict[str, Any]], pages_dir: Path) -> None:
    """Generate one static HTML page per CNA under pages_dir/<slug>/index.html."""
    pages_dir.mkdir(parents=True, exist_ok=True)

    data_dir = pages_dir.parent / "assets" / "data" / "cna"
    data_dir.mkdir(parents=True, exist_ok=True)

    leaderboard = summary["cna"]["leaderboard"]

    # Build directory page rows and write CNA shards.
    for entry in leaderboard:
        slug = entry["slug"]
        shard = shard_exports.get(slug)
        if shard is None:
            continue
        (data_dir / f"{slug}.json").write_text(json.dumps(shard, indent=2), encoding="utf-8")

    index_rows = ""
    for entry in leaderboard:
        cna_name = entry["cna"]
        slug = entry["slug"]
        rank = entry.get("rank", "--")
        heartbeat = entry.get("window30SecondsPerCve")
        total = entry.get("totalEvents", 0)
        hb_display = format_heartbeat(heartbeat) if heartbeat else "N/A"

        index_rows += f"""      <tr class="border-b border-sky-200/70 dark:border-white/5 hover:bg-sky-100/70 dark:hover:bg-white/5 transition-colors">
        <td class="py-2.5 pr-3 text-slate-500 dark:text-slate-400">{rank}</td>
        <td class="py-2.5 pr-3"><a href="{slug}/" class="text-slate-900 dark:text-cyan-300 hover:text-sky-600 dark:hover:underline transition-colors">{cna_name}</a></td>
        <td class="py-2.5 pr-3 text-sky-700 dark:text-cyan-200">{hb_display}</td>
        <td class="py-2.5 text-slate-700 dark:text-slate-300">{total:,}</td>
      </tr>\n"""

    index_html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CNA Profiles · CVETime</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {{
        darkMode: 'class',
        theme: {{
          extend: {{
            colors: {{
              ink: {{ DEFAULT: "#06101d", light: "#f8fafc" }},
              panel: {{ DEFAULT: "#10233c", light: "#f1f5f9" }},
              accent: {{ DEFAULT: "#2ee6ff", light: "#0ea5e9" }}
            }}
          }}
        }}
      }};
    </script>
  </head>
  <body class="bg-ink-light text-slate-900 dark:bg-ink dark:text-slate-100 min-h-screen transition-colors duration-300">
    <div class="fixed inset-0 -z-20 bg-[radial-gradient(circle_at_15%_15%,rgba(14,165,233,0.14),transparent_30%),radial-gradient(circle_at_80%_0%,rgba(99,102,241,0.12),transparent_26%),radial-gradient(circle_at_90%_90%,rgba(20,184,166,0.10),transparent_22%),linear-gradient(180deg,#f8fbff_0%,#eff6ff_48%,#e0f2fe_100%)] dark:bg-[radial-gradient(circle_at_15%_15%,rgba(46,230,255,0.15),transparent_28%),radial-gradient(circle_at_80%_0%,rgba(96,165,250,0.15),transparent_26%),radial-gradient(circle_at_90%_90%,rgba(45,212,191,0.10),transparent_22%),linear-gradient(180deg,#040a13_0%,#081321_48%,#06101d_100%)]"></div>
    <div class="fixed inset-0 -z-10 opacity-40 dark:opacity-30 bg-[linear-gradient(rgba(14,165,233,0.07)_1px,transparent_1px),linear-gradient(90deg,rgba(14,165,233,0.07)_1px,transparent_1px)] dark:bg-[linear-gradient(rgba(148,163,184,0.07)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.07)_1px,transparent_1px)] bg-[size:88px_88px]"></div>
    <script>
      (function() {{
        const saved = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (saved === 'dark' || (!saved && prefersDark)) document.documentElement.classList.add('dark');
      }})();
    </script>
    <header class="sticky top-0 z-20 border-b border-sky-200/80 dark:border-white/10 bg-[rgba(248,250,252,0.78)] dark:bg-slate-950/90 backdrop-blur-xl">
      <div class="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
        <a href="../" class="text-xs text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-cyan-400 transition-colors">← Global Dashboard</a>
        <span class="text-slate-400 dark:text-slate-600">/</span>
        <span class="text-xs text-slate-900 dark:text-slate-200">CNA Directory</span>
        <div class="ml-auto">
          <button id="themeToggle" class="px-2 py-1 rounded bg-white/70 dark:bg-white/5 border border-sky-200/80 dark:border-white/10 text-xs text-slate-700 dark:text-slate-300 hover:bg-sky-100 dark:hover:bg-cyan-400/10 transition-colors">
            <span id="themeIcon">🌙</span> Theme
          </button>
        </div>
      </div>
    </header>
    <script>
      (function() {{
        const root = document.documentElement;
        const toggle = document.getElementById('themeToggle');
        const icon = document.getElementById('themeIcon');
        function setTheme(mode) {{
          if (mode === 'dark') {{
            root.classList.add('dark');
            icon.textContent = '🌙';
            localStorage.setItem('theme', 'dark');
          }} else {{
            root.classList.remove('dark');
            icon.textContent = '☀️';
            localStorage.setItem('theme', 'light');
          }}
        }}
        icon.textContent = root.classList.contains('dark') ? '🌙' : '☀️';
        toggle.addEventListener('click', () => {{
          setTheme(root.classList.contains('dark') ? 'light' : 'dark');
        }});
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {{
          if (!localStorage.getItem('theme')) setTheme(e.matches ? 'dark' : 'light');
        }});
      }})();
    </script>
    <main class="max-w-6xl mx-auto px-4 py-8">
      <div class="max-w-3xl mb-6">
        <h1 class="font-display text-3xl md:text-5xl font-semibold mt-1 text-slate-950 dark:text-white">CNA Directory</h1>
        <p class="text-slate-700 dark:text-slate-300/90 mt-3 text-base md:text-lg">Search and sort the publisher leaderboard without leaving the directory page.</p>
      </div>

      <section class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 p-4 md:p-6 mb-6 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none">
        <div class="flex flex-col md:flex-row md:items-center gap-3 justify-between mb-4">
          <div class="flex items-center gap-2">
            <label for="directorySearch" class="text-xs text-slate-600 dark:text-slate-300">Search</label>
            <input id="directorySearch" type="search" placeholder="Find a CNA" class="w-64 max-w-full rounded-lg border border-sky-200/80 dark:border-white/10 bg-white/80 dark:bg-slate-900 px-3 py-2 text-sm text-slate-900 dark:text-slate-100" />
          </div>
          <div class="flex items-center gap-2">
            <label for="directorySort" class="text-xs text-slate-600 dark:text-slate-300">Sort</label>
            <select id="directorySort" class="rounded-lg border border-sky-200/80 dark:border-white/10 bg-white/80 dark:bg-slate-900 px-3 py-2 text-sm text-slate-900 dark:text-slate-100">
              <option value="rank-asc" selected>Rank</option>
              <option value="heartbeat-asc">Fastest heartbeat</option>
              <option value="heartbeat-desc">Slowest heartbeat</option>
              <option value="total-desc">Most CVEs</option>
              <option value="name-asc">Name A-Z</option>
            </select>
            <div id="directoryCount" class="text-xs text-slate-500 dark:text-slate-400"></div>
          </div>
        </div>

        <div class="overflow-x-auto rounded-xl border border-sky-200/80 dark:border-white/10">
          <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-slate-500 dark:text-slate-400 border-b border-sky-200/80 dark:border-white/10 text-xs uppercase tracking-wider">
              <th class="py-3 pr-3 pl-4">Rank</th>
              <th class="py-3 pr-3">CNA</th>
              <th class="py-3 pr-3">30d Interval</th>
              <th class="py-3 pr-4">Total CVEs</th>
            </tr>
          </thead>
          <tbody id="directoryTable" class="pl-4"></tbody>
        </table>
        </div>
      </section>
    </main>
    <script defer src="../assets/js/main.js"></script>
    <script>
      window.CVE_TIME_SUMMARY_PATH = "../assets/data/summary.json";
    </script>
  </body>
</html>
"""
    (pages_dir / "index.html").write_text(index_html, encoding="utf-8")

    # Generate individual CNA pages
    for entry in leaderboard:
        cna_name = entry["cna"]
        slug = entry["slug"]

        page_dir = pages_dir / slug
        page_dir.mkdir(parents=True, exist_ok=True)

        html = CNA_TEMPLATE.format(
            cna_name=cna_name,
            slug=slug,
        )
        (page_dir / "index.html").write_text(html, encoding="utf-8")

    # Generate sitemap.xml in docs/
    docs_dir = pages_dir.parent
    base_url = "https://gamblin.github.io/CVETime"
    sitemap_urls = [
        f"  <url><loc>{base_url}/</loc></url>",
        f"  <url><loc>{base_url}/cna/</loc></url>",
    ] + [
        f"  <url><loc>{base_url}/cna/{entry['slug']}/</loc></url>"
        for entry in leaderboard
    ]
    sitemap = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
    sitemap += "\n".join(sitemap_urls)
    sitemap += "\n</urlset>\n"
    (docs_dir / "sitemap.xml").write_text(sitemap, encoding="utf-8")

    print(f"Generated {len(leaderboard)} CNA pages + index under {pages_dir}")
    print(f"Generated sitemap.xml at {docs_dir / 'sitemap.xml'}")


def main() -> None:
    args = parse_args()
    summary, shard_exports = build_summary(args.cvelist_path)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote summary to {args.output}")

    if args.cna_pages_dir is not None:
        generate_cna_pages(summary, shard_exports, args.cna_pages_dir)


if __name__ == "__main__":
    main()

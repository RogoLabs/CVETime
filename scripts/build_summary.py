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


def monthly_deltas(timestamps: pd.Series) -> pd.Series:
    timeline = pd.Series(pd.to_datetime(timestamps, utc=True), copy=False).drop_duplicates().sort_values()
    if timeline.shape[0] < 2:
        return pd.Series(dtype="float64")

    indexed_timeline = pd.Series(timeline.values, index=pd.DatetimeIndex(timeline.values))
    return indexed_timeline.diff().dt.total_seconds().dropna()


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
                "slug": to_slug(str(cna)),
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

        deltas = monthly_deltas(unique_seconds)
        monthly = deltas.resample("MS").agg(
            mean="mean",
            median="median",
            count="count",
            p25=lambda x: float(x.quantile(0.25)),
            p75=lambda x: float(x.quantile(0.75)),
        ).dropna()
        trend_by_cna[cna] = [
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
              ink2: {{ DEFAULT: "#0b1727", light: "#e2e8f0" }},
              panel: {{ DEFAULT: "#10233c", light: "#f1f5f9" }},
              panel2: {{ DEFAULT: "#162b46", light: "#e0e7ef" }},
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
      // Sync theme from root
      (function() {{
        const saved = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (saved === 'dark' || (!saved && prefersDark)) document.documentElement.classList.add('dark');
      }})();
    </script>

    <header class="sticky top-0 z-20 border-b border-sky-200/80 dark:border-white/10 bg-[rgba(248,250,252,0.78)] dark:bg-slate-950/90 backdrop-blur-xl">
      <div class="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
        <a href="../../" class="text-xs text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-cyan-400 transition-colors">← Global Dashboard</a>
        <span class="text-slate-400 dark:text-slate-600">/</span>
        <a href="../" class="text-xs text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-cyan-400 transition-colors">CNAs</a>
        <span class="text-slate-400 dark:text-slate-600">/</span>
        <span class="text-xs text-slate-900 dark:text-slate-200">{cna_name}</span>
        <div class="ml-auto">
          <button id="themeToggle" class="px-2 py-1 rounded bg-white/70 dark:bg-white/5 border border-sky-200/80 dark:border-white/10 text-xs text-slate-700 dark:text-slate-300 hover:bg-sky-100 dark:hover:bg-cyan-400/10 transition-colors">
            <span id="themeIcon">🌙</span> Theme
          </button>
        </div>
      </div>
    </header>

    <main class="max-w-5xl mx-auto px-4 py-8">

      <div class="mb-8">
        <p class="text-xs uppercase tracking-widest text-sky-700 dark:text-cyan-400 mb-2">CNA Profile</p>
        <h1 class="text-3xl md:text-4xl font-semibold text-slate-950 dark:text-white">{cna_name}</h1>
        <p class="text-slate-600 dark:text-slate-400 mt-1 text-sm">Publication velocity trend and peer comparison</p>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8">
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">30d Heartbeat</p>
          <p id="hero30d" class="text-2xl font-semibold text-accent-light dark:text-cyan-400 mt-1">--</p>
        </div>
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">Rank</p>
          <p id="heroRank" class="text-2xl font-semibold text-accent3-light dark:text-sky-400 mt-1">--</p>
        </div>
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">Faster than</p>
          <p id="heroPercentile" class="text-2xl font-semibold text-accent2-light dark:text-teal-400 mt-1">--</p>
        </div>
        <div class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-white/70 dark:bg-white/4 px-4 py-3 shadow-[0_12px_36px_rgba(14,165,233,0.08)] dark:shadow-none">
          <p class="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">Total CVEs</p>
          <p id="heroTotal" class="text-2xl font-semibold text-indigo-600 dark:text-indigo-400 mt-1">--</p>
        </div>
      </div>

      <section class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 p-4 md:p-6 mb-8 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none">
        <div class="flex items-center justify-between gap-3 mb-4 flex-wrap">
          <div>
            <h2 class="text-lg font-semibold text-slate-950 dark:text-white">Publication Interval Trend</h2>
            <p class="text-xs text-slate-500 dark:text-slate-400">Monthly mean with 25th–75th percentile band</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap justify-end">
            <label for="rangeToggle" class="text-xs text-slate-600 dark:text-slate-300">Range:</label>
            <select id="rangeToggle" class="bg-white/80 dark:bg-slate-900 border border-sky-200/80 dark:border-white/10 rounded px-2 py-1 text-xs text-slate-900 dark:text-slate-100">
              <option value="recent" selected>2017+</option>
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

      <section class="rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 p-4 md:p-6 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none">
        <h2 class="text-lg font-semibold text-slate-950 dark:text-white mb-4">Top 20 CNAs by Heartbeat</h2>
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
      const CNA_SLUG = {slug_json};
      const SUMMARY_PATH = "../../assets/data/summary.json";

      function formatDuration(seconds) {{
        if (seconds == null || isNaN(seconds)) return "--";
        seconds = Math.round(seconds);
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;
        let out = [];
        if (d > 0) out.push(d + "d");
        if (h > 0) out.push(h + "h");
        if (m > 0) out.push(m + "m");
        if (s > 0 || out.length === 0) out.push(s + "s");
        return out.join(" ");
      }}

      function fmtNumber(v) {{
        if (v == null || isNaN(v)) return "--";
        return new Intl.NumberFormat().format(v);
      }}

      let cnaChart;
      let currentRange = 'recent';

      function isDark() {{
        return document.documentElement.classList.contains('dark');
      }}

      function getTrendPoints(trend, range = 'recent') {{
        if (range === 'all') return trend;
        return trend.filter(point => point.date >= '2017-01-01');
      }}

      function renderChart(trend, scale, range) {{
        const ctx = document.getElementById('cnaChart').getContext('2d');
        if (cnaChart) cnaChart.destroy();

        const dark = isDark();
        const points = getTrendPoints(trend, range);
        const labels = points.map(p => p.date);
        const mean = points.map(p => p.avgIntervalSeconds);
        const p25 = points.map(p => p.p25IntervalSeconds);
        const p75 = points.map(p => p.p75IntervalSeconds);
        const tickColor = dark ? '#94a3b8' : '#64748b';
        const gridColor = dark ? 'rgba(148,163,184,0.10)' : 'rgba(100,116,139,0.08)';

        cnaChart = new Chart(ctx, {{
          type: 'line',
          data: {{
            labels,
            datasets: [
              {{
                label: 'P25–P75 band',
                data: p75,
                fill: '+1',
                borderColor: 'transparent',
                backgroundColor: dark ? 'rgba(46,230,255,0.10)' : 'rgba(14,165,233,0.10)',
                pointRadius: 0,
                tension: 0.25,
                order: 3
              }},
              {{
                label: 'P25',
                data: p25,
                fill: false,
                borderColor: 'transparent',
                backgroundColor: 'transparent',
                pointRadius: 0,
                tension: 0.25,
                order: 4
              }},
              {{
                label: 'Mean interval',
                data: mean,
                borderColor: dark ? 'rgba(46,230,255,0.95)' : '#0ea5e9',
                backgroundColor: 'transparent',
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
            interaction: {{ mode: 'index', intersect: false }},
            plugins: {{
              legend: {{ display: false }},
              tooltip: {{
                backgroundColor: dark ? 'rgba(6,16,29,0.96)' : '#f1f5f9',
                titleColor: dark ? '#f8fafc' : '#0f172a',
                bodyColor: dark ? '#dbeafe' : '#334155',
                callbacks: {{
                  label: function(ctx) {{
                    if (ctx.dataset.label === 'P25') return 'P25: ' + formatDuration(ctx.parsed.y);
                    if (ctx.dataset.label === 'P25–P75 band') return 'P75: ' + formatDuration(ctx.parsed.y);
                    return ctx.dataset.label + ': ' + formatDuration(ctx.parsed.y);
                  }}
                }}
              }}
            }},
            scales: {{
              x: {{ ticks: {{ color: tickColor }}, grid: {{ color: gridColor }} }},
              y: {{
                type: scale,
                min: scale === 'logarithmic' ? undefined : 0,
                ticks: {{ color: tickColor, callback: (v) => formatDuration(v) }},
                grid: {{ color: gridColor }},
                title: {{ display: true, text: 'Interval per CVE', color: dark ? '#94a3b8' : '#64748b' }}
              }}
            }}
          }}
        }});
      }}

      async function boot() {{
        const themeToggle = document.getElementById('themeToggle');
        const themeIcon = document.getElementById('themeIcon');

        function setTheme(mode) {{
          if (mode === 'dark') {{
            document.documentElement.classList.add('dark');
            themeIcon.textContent = '🌙';
            localStorage.setItem('theme', 'dark');
          }} else {{
            document.documentElement.classList.remove('dark');
            themeIcon.textContent = '☀️';
            localStorage.setItem('theme', 'light');
          }}
        }}

        const saved = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        setTheme(saved || (prefersDark ? 'dark' : 'light'));
        themeIcon.textContent = isDark() ? '🌙' : '☀️';

        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {{
          if (!localStorage.getItem('theme')) setTheme(e.matches ? 'dark' : 'light');
        }});
        themeToggle.addEventListener('click', () => {{
          setTheme(isDark() ? 'light' : 'dark');
          if (cnaChart) renderChart(window._cnaTrend, document.getElementById('scaleToggle').value, currentRange);
        }});

        const resp = await fetch(SUMMARY_PATH, {{ cache: 'no-store' }});
        const data = await resp.json();
        const entry = (data.cna.leaderboard || []).find(r => r.slug === CNA_SLUG);
        const trend = (data.cna.trendByCna || {{}})[entry?.cna] || [];
        window._cnaTrend = trend;

        if (entry) {{
          document.getElementById('hero30d').textContent = formatDuration(entry.window30SecondsPerCve);
          document.getElementById('heroRank').textContent = '#' + (entry.rank ?? '--');
          document.getElementById('heroPercentile').textContent = (entry.percentileFaster ?? '--') + '%';
          document.getElementById('heroTotal').textContent = fmtNumber(entry.totalEvents);
        }}

        let scale = 'linear';
        renderChart(trend, scale, currentRange);

        document.getElementById('rangeToggle').addEventListener('change', e => {{
          currentRange = e.target.value;
          renderChart(trend, scale, currentRange);
        }});

        document.getElementById('scaleToggle').addEventListener('change', e => {{
          scale = e.target.value;
          renderChart(trend, scale, currentRange);
        }});

        // Peer table — top 20
        const tbody = document.getElementById('peerTable');
        (data.cna.leaderboard || []).slice(0, 20).forEach(row => {{
          const isCurrent = row.slug === CNA_SLUG;
          const tr = document.createElement('tr');
          tr.className = 'border-b border-sky-200/70 dark:border-white/5 ' + (isCurrent ? 'bg-sky-100/90 dark:bg-cyan-400/10 font-semibold' : 'hover:bg-sky-100/70 dark:hover:bg-white/5') + ' transition-colors';
          tr.innerHTML = `
            <td class="py-2 pr-3 text-slate-500 dark:text-slate-400">${{row.rank ?? '--'}}</td>
            <td class="py-2 pr-3">${{isCurrent
              ? '<span class="text-sky-700 dark:text-cyan-300">' + row.cna + '</span>'
              : '<a href="../' + row.slug + '/" class="text-slate-900 dark:text-slate-200 hover:text-sky-600 dark:hover:text-cyan-300 transition-colors">' + row.cna + '</a>'
            }}</td>
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


def generate_cna_pages(summary: dict[str, Any], pages_dir: Path) -> None:
    """Generate one static HTML page per CNA under pages_dir/<slug>/index.html."""
    pages_dir.mkdir(parents=True, exist_ok=True)

    leaderboard = summary["cna"]["leaderboard"]

    # Build index page listing all CNAs
    index_rows = ""
    for entry in leaderboard:
        cna_name = entry["cna"]
        slug = entry["slug"]
        rank = entry.get("rank", "--")
        heartbeat = entry.get("window30SecondsPerCve")
        total = entry.get("totalEvents", 0)

        # Format heartbeat for display
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
              panel: {{ DEFAULT: "#10233c", light: "#f1f5f9" }}
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
      <div class="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
        <a href="../" class="text-xs text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-cyan-400 transition-colors">← Global Dashboard</a>
        <span class="text-slate-400 dark:text-slate-600">/</span>
        <span class="text-xs text-slate-900 dark:text-slate-200">CNA Profiles</span>
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
    <main class="max-w-5xl mx-auto px-4 py-8">
      <h1 class="text-3xl font-semibold text-slate-950 dark:text-white mb-2">CNA Profiles</h1>
      <p class="text-slate-600 dark:text-slate-400 mb-6 text-sm">Individual publication velocity for each CVE Numbering Authority</p>
      <div class="overflow-x-auto rounded-2xl border border-sky-200/80 dark:border-white/10 bg-panel-light/90 dark:bg-white/3 shadow-[0_18px_60px_rgba(14,165,233,0.10)] dark:shadow-none">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-slate-500 dark:text-slate-400 border-b border-sky-200/80 dark:border-white/10 text-xs uppercase tracking-wider">
              <th class="py-3 pr-3 pl-4">Rank</th>
              <th class="py-3 pr-3">CNA</th>
              <th class="py-3 pr-3">30d Interval</th>
              <th class="py-3 pr-4">Total CVEs</th>
            </tr>
          </thead>
          <tbody class="pl-4">
{index_rows}          </tbody>
        </table>
      </div>
    </main>
  </body>
</html>
"""
    (pages_dir / "index.html").write_text(index_html, encoding="utf-8")

    # Generate individual CNA pages
    for entry in leaderboard:
        cna_name = entry["cna"]
        slug = entry["slug"]
        slug_json = json.dumps(slug)

        page_dir = pages_dir / slug
        page_dir.mkdir(parents=True, exist_ok=True)

        html = CNA_TEMPLATE.format(
            cna_name=cna_name,
            slug=slug,
            slug_json=slug_json,
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
    summary = build_summary(args.cvelist_path)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote summary to {args.output}")

    if args.cna_pages_dir is not None:
        generate_cna_pages(summary, args.cna_pages_dir)


if __name__ == "__main__":
    main()

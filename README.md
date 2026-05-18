# CVETime
Visualizing the time elapsed between CVE publications for the global community and individual CNAs.

## Overview

CVETime is a static dashboard that tracks CVE publication velocity:

- Global heartbeat: average time between new CVE publications.
- Global trend: monthly mean and median publication interval trends.
- CNA velocity table: rolling publication interval metrics by CNA.

The project is designed for automated refresh on GitHub Pages.

## Tech Stack

- Data processing: Python + Pandas
- Frontend: Tailwind CSS + Chart.js
- Automation and hosting: GitHub Actions + GitHub Pages

## Repository Layout

- `scripts/build_summary.py`: parses cvelistV5 and writes dashboard summary data.
- `docs/index.html`: static dashboard page served by GitHub Pages.
- `docs/assets/js/main.js`: dashboard rendering logic.
- `docs/assets/data/summary.json`: generated summary dataset consumed by the frontend.
- `.github/workflows/update-dashboard.yml`: scheduled data refresh and Pages deployment.

## Local Development

### 1) Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 2) Prepare CVE data source

Clone cvelistV5 locally:

```bash
git clone --depth=1 https://github.com/CVEProject/cvelistV5.git .cache/cvelistV5
```

### 3) Build summary data

```bash
python3 scripts/build_summary.py \
	--cvelist-path .cache/cvelistV5 \
	--output docs/assets/data/summary.json
```

### 4) Run static site locally

Use any simple static web server from repo root:

```bash
python3 -m http.server 8080
```

Then open `http://localhost:8080/docs/`.

## Data Notes

- The parser reads `datePublished` and CNA metadata with schema fallbacks.
- Same-second publication events are collapsed to a logical single event for interval metrics.
- Rolling windows in summary output include 30-day and 90-day global metrics, plus per-CNA rollups.

## GitHub Actions Automation

Workflow: `.github/workflows/update-dashboard.yml`

- Runs daily at `00:00 UTC` and via manual dispatch.
- Refreshes cvelistV5 using depth-limited clone/fetch.
- Rebuilds `docs/assets/data/summary.json`.
- Commits updated summary data only when changed.
- Deploys `docs/` to GitHub Pages using official Pages actions.

## GitHub Pages Setup

In repository settings:

1. Enable GitHub Pages.
2. Set Source to GitHub Actions.

No additional server is required.

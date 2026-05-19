const SUMMARY_PATH = window.CVE_TIME_SUMMARY_PATH || "assets/data/summary.json";

function fmtNumber(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return new Intl.NumberFormat().format(value);
}


function formatDuration(seconds) {
  if (seconds == null || isNaN(seconds)) return "--";
  seconds = Math.round(seconds);
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  let out = [];
  if (d > 0) out.push(`${d}d`);
  if (h > 0) out.push(`${h}h`);
  if (m > 0) out.push(`${m}m`);
  if (s > 0 || out.length === 0) out.push(`${s}s`);
  return out.join(" ");
}

function renderOverview(data) {
  document.getElementById("heroMetric").textContent = data.global.heartbeat.display || "--";
  document.getElementById("generatedAt").textContent = `Updated: ${new Date(data.generatedAt).toUTCString()}`;
  document.getElementById("distinctCnas").textContent = fmtNumber(data.stats.distinctCnas);
  document.getElementById("parsedRecords").textContent = fmtNumber(data.stats.parsedRecords);
}

function renderSupplementalCharts(data, range = currentRange) {
  const volumeCanvas = document.getElementById("monthlyVolumeChart");
  const cnaCanvas = document.getElementById("cnaVelocityChart");
  if (!volumeCanvas && !cnaCanvas) return;

  const colors = getChartColors();

  if (volumeCanvas) {
    const points = getGlobalTrendPoints(data, range);
    if (monthlyVolumeChart) monthlyVolumeChart.destroy();
    monthlyVolumeChart = new Chart(volumeCanvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: points.map((point) => point.date),
        datasets: [{
          label: "CVE count",
          data: points.map((point) => point.eventCount),
          backgroundColor: colors.volumeFill,
          borderColor: colors.volume,
          borderWidth: 1.5,
          borderRadius: 6,
          maxBarThickness: 14,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: colors.tooltipBg,
            borderColor: colors.tooltipBorder,
            borderWidth: 1,
            titleColor: colors.tooltipTitle,
            bodyColor: colors.tooltipBody,
            callbacks: {
              label(context) {
                return `${context.parsed.y} CVEs`;
              },
            },
          },
        },
        scales: {
          x: { ticks: { color: colors.xTicks, maxRotation: 0 }, grid: { color: colors.xGrid } },
          y: {
            beginAtZero: true,
            ticks: { color: colors.yTicks, precision: 0 },
            grid: { color: colors.yGrid },
            title: { display: true, text: "Published CVEs", color: colors.yTitle },
          },
        },
      },
    });
  }

  if (cnaCanvas) {
    const leaderboard = Array.isArray(data.cna?.leaderboard) ? data.cna.leaderboard.slice(0, 10) : [];
    if (cnaVelocityChart) cnaVelocityChart.destroy();
    cnaVelocityChart = new Chart(cnaCanvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: leaderboard.map((row) => row.cna),
        datasets: [{
          label: "30d interval",
          data: leaderboard.map((row) => row.window30SecondsPerCve),
          backgroundColor: colors.cnaFill,
          borderColor: colors.cna,
          borderWidth: 1.5,
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: colors.tooltipBg,
            borderColor: colors.tooltipBorder,
            borderWidth: 1,
            titleColor: colors.tooltipTitle,
            bodyColor: colors.tooltipBody,
            callbacks: {
              label(context) {
                return formatDuration(context.parsed.x);
              },
            },
          },
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { color: colors.xTicks, callback: (value) => formatDuration(value) },
            grid: { color: colors.xGrid },
            title: { display: true, text: "Seconds per CVE", color: colors.yTitle },
          },
          y: { ticks: { color: colors.yTicks }, grid: { color: colors.yGrid } },
        },
      },
    });
  }
}

function renderDashboardCharts(data, scale = currentScale, range = currentRange) {
  renderOverview(data);
  renderGlobalTrend(data, scale, range);
  renderSupplementalCharts(data, range);
}


let globalChart;
let monthlyVolumeChart;
let cnaVelocityChart;
let currentScale = "linear";
let currentRange = "24m";

function getChartColors() {
  const isDark = document.documentElement.classList.contains('dark');
  return {
    mean: isDark ? "rgba(46, 230, 255, 0.95)" : "#0ea5e9",
    meanPoint: isDark ? "rgba(46, 230, 255, 1)" : "#0ea5e9",
    meanBorder: isDark ? "rgba(4, 10, 19, 1)" : "#f1f5f9",
    median: isDark ? "rgba(96, 165, 250, 0.90)" : "#6366f1",
    band: isDark ? "rgba(46, 230, 255, 0.10)" : "rgba(14, 165, 233, 0.10)",
    legend: isDark ? "#dbeafe" : "#334155",
    tooltipBg: isDark ? "rgba(6, 16, 29, 0.96)" : "#f1f5f9",
    tooltipBorder: isDark ? "rgba(46, 230, 255, 0.24)" : "#0ea5e9",
    tooltipTitle: isDark ? "#f8fafc" : "#0f172a",
    tooltipBody: isDark ? "#dbeafe" : "#334155",
    annotation: isDark ? "#2ee6ff" : "#0ea5e9",
    annotationBg: isDark ? "rgba(46,230,255,0.13)" : "#bae6fd",
    xTicks: isDark ? "#94a3b8" : "#64748b",
    xGrid: isDark ? "rgba(148, 163, 184, 0.12)" : "rgba(100,116,139,0.10)",
    yTicks: isDark ? "#94a3b8" : "#64748b",
    yGrid: isDark ? "rgba(148, 163, 184, 0.12)" : "rgba(100,116,139,0.10)",
    yTitle: isDark ? "#cbd5e1" : "#334155",
    volume: isDark ? "rgba(96, 165, 250, 0.95)" : "#6366f1",
    volumeFill: isDark ? "rgba(96, 165, 250, 0.22)" : "rgba(99, 102, 241, 0.18)",
    cna: isDark ? "rgba(45, 212, 191, 0.95)" : "#14b8a6",
    cnaFill: isDark ? "rgba(45, 212, 191, 0.24)" : "rgba(20, 184, 166, 0.18)",
  };
}

function getGlobalTrendPoints(data, range = "24m") {
  const points = data.global.trend || [];
  if (range === "all") {
    return points;
  }
  if (range === "24m") {
    // Calculate date 24 months ago from today
    const now = new Date();
    const twentyFourMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 24, 1);
    const cutoffDate = twentyFourMonthsAgo.toISOString().split('T')[0];
    return points.filter((point) => point.date >= cutoffDate);
  }
  // Default to 2017+
  return points.filter((point) => point.date >= "2017-01-01");
}

function renderGlobalTrend(data, scale = "linear", range = "24m") {
  const points = getGlobalTrendPoints(data, range);
  const labels = points.map((p) => p.date);
  const meanValues = points.map((p) => p.avgIntervalSeconds);
  const medianValues = points.map((p) => p.medianIntervalSeconds);
  const p75Values = points.map((p) => p.p75IntervalSeconds ?? p.avgIntervalSeconds);
  const p25Values = points.map((p) => p.p25IntervalSeconds ?? p.avgIntervalSeconds);

  const ctx = document.getElementById("globalTrendChart").getContext("2d");
  if (globalChart) globalChart.destroy();

  // Annotation: first date >= 2003-01-01, only when showing full history
  const annotationIndex = range === "all" ? labels.findIndex((d) => d >= "2003-01-01") : -1;
  const annotationDate = annotationIndex !== -1 ? labels[annotationIndex] : null;

  // Theme-aware colors
  const colors = getChartColors();

  globalChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        // P75 upper bound (fill down to P25)
        {
          label: "P75",
          data: p75Values,
          fill: "+1",
          borderColor: "transparent",
          backgroundColor: colors.band,
          pointRadius: 0,
          tension: 0.25,
          order: 4,
        },
        // P25 lower bound
        {
          label: "P25",
          data: p25Values,
          fill: false,
          borderColor: "transparent",
          backgroundColor: "transparent",
          pointRadius: 0,
          tension: 0.25,
          order: 5,
        },
        // Mean line (primary — on top)
        {
          label: "Mean interval",
          data: meanValues,
          borderColor: colors.mean,
          backgroundColor: "transparent",
          pointBackgroundColor: colors.meanPoint,
          pointBorderColor: colors.meanBorder,
          pointRadius: 2,
          pointHoverRadius: 5,
          borderWidth: 2.5,
          tension: 0.25,
          order: 1,
        },
        // Median line
        {
          label: "Median",
          data: medianValues,
          borderColor: colors.median,
          backgroundColor: "transparent",
          pointRadius: 0,
          borderWidth: 1.5,
          borderDash: [4, 3],
          tension: 0.25,
          order: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: {
            color: colors.legend,
            usePointStyle: true,
            boxWidth: 10,
            filter: (item) => item.text !== "P25" && item.text !== "P75",
          },
        },
        tooltip: {
          backgroundColor: colors.tooltipBg,
          borderColor: colors.tooltipBorder,
          borderWidth: 1,
          titleColor: colors.tooltipTitle,
          bodyColor: colors.tooltipBody,
          callbacks: {
            label: function(context) {
              const label = context.dataset.label || "";
              const value = context.parsed.y;
              if (label === "P75") return `P75: ${formatDuration(value)}`;
              if (label === "P25") return `P25: ${formatDuration(value)}`;
              return `${label}: ${formatDuration(value)}`;
            }
          }
        },
        annotation: annotationDate
          ? {
              annotations: {
                regimeChange: {
                  type: "line",
                  xMin: annotationDate,
                  xMax: annotationDate,
                  borderColor: colors.annotation,
                  borderWidth: 2,
                  borderDash: [6, 6],
                  label: {
                    content: ["2003: CVE volume shift"],
                    enabled: true,
                    position: "start",
                    backgroundColor: colors.annotationBg,
                    color: colors.annotation,
                    font: { size: 11, weight: "bold" },
                    yAdjust: 10,
                    xAdjust: 0,
                    padding: 4,
                  },
                },
              },
            }
          : undefined,
      },
      scales: {
        x: {
          ticks: { color: colors.xTicks },
          grid: { color: colors.xGrid },
        },
        y: {
          type: scale,
          min: scale === "logarithmic" ? undefined : 0,
          ticks: {
            color: colors.yTicks,
            callback: function (value) {
              return formatDuration(value);
            },
          },
          grid: { color: colors.yGrid },
          title: {
            display: true,
            text: "Average interval per CVE",
            color: colors.yTitle,
          },
        },
      },
    },
    plugins: [window.ChartAnnotationPlugin].filter(Boolean),
  });

  // Listen for theme changes and update chart
  if (!window._chartThemeListener) {
    window._chartThemeListener = true;
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      renderDashboardCharts(data, currentScale, currentRange);
    });
    document.getElementById('themeToggle').addEventListener('click', () => {
      setTimeout(() => renderDashboardCharts(data, currentScale, currentRange), 100);
    });
  }
}

function renderCnaDirectory(data) {
  const tableBody = document.getElementById("directoryTable");
  if (!tableBody) return;

  const searchInput = document.getElementById("directorySearch");
  const sortSelect = document.getElementById("directorySort");
  const countLabel = document.getElementById("directoryCount");
  const sourceRows = Array.isArray(data.cna?.leaderboard) ? data.cna.leaderboard.slice() : [];

  const sorters = {
    "rank-asc": (a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9),
    "heartbeat-asc": (a, b) => (a.window30SecondsPerCve ?? Infinity) - (b.window30SecondsPerCve ?? Infinity),
    "heartbeat-desc": (a, b) => (b.window30SecondsPerCve ?? -Infinity) - (a.window30SecondsPerCve ?? -Infinity),
    "total-desc": (a, b) => (b.totalEvents ?? 0) - (a.totalEvents ?? 0),
    "name-asc": (a, b) => String(a.cna || "").localeCompare(String(b.cna || "")),
  };

  function render() {
    const query = String(searchInput?.value || "").trim().toLowerCase();
    const sortKey = sortSelect?.value || "rank-asc";
    const rows = sourceRows
      .filter((item) => !query || String(item.cna || "").toLowerCase().includes(query) || String(item.slug || "").toLowerCase().includes(query))
      .sort(sorters[sortKey] || sorters["rank-asc"]);

    tableBody.innerHTML = "";
    if (rows.length === 0) {
      tableBody.innerHTML = '<tr><td class="py-4 text-slate-500 dark:text-slate-400" colspan="4">No CNAs matched your search.</td></tr>';
      if (countLabel) countLabel.textContent = "0 CNAs";
      return;
    }

    for (const item of rows) {
      const tr = document.createElement("tr");
      tr.className = "border-b border-sky-200/70 dark:border-white/5 hover:bg-sky-100/70 dark:hover:bg-white/5 transition-colors";
      tr.innerHTML = `
        <td class="py-2.5 pr-3 text-slate-500 dark:text-slate-400">${item.rank ?? "--"}</td>
        <td class="py-2.5 pr-3 text-slate-900 dark:text-slate-100"><a class="hover:text-sky-600 dark:hover:text-cyan-300 transition-colors" href="${item.slug}/">${item.cna}</a></td>
        <td class="py-2.5 pr-3 text-sky-700 dark:text-cyan-200">${formatDuration(item.window30SecondsPerCve)}</td>
        <td class="py-2.5 text-slate-700 dark:text-slate-300">${fmtNumber(item.totalEvents)}</td>
      `;
      tableBody.appendChild(tr);
    }

    if (countLabel) countLabel.textContent = `${rows.length} CNA${rows.length === 1 ? "" : "s"}`;
  }

  searchInput?.addEventListener("input", render);
  sortSelect?.addEventListener("change", render);
  render();
}


async function boot() {
  // Load Chart.js annotation plugin if available
  if (!window.ChartAnnotationPlugin && window.Chart) {
    try {
      const mod = await import('https://cdn.jsdelivr.net/npm/chartjs-plugin-annotation@4.1.1/dist/chartjs-plugin-annotation.min.js');
      window.ChartAnnotationPlugin = mod.default || mod;
    } catch (e) {
      window.ChartAnnotationPlugin = undefined;
    }
  }
  try {
    const response = await fetch(SUMMARY_PATH, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to fetch summary.json: ${response.status}`);
    }

    const data = await response.json();
    if (document.getElementById("globalTrendChart")) {
      renderDashboardCharts(data, currentScale, currentRange);
    }

    if (document.getElementById("directoryTable")) {
      renderCnaDirectory(data);
    }

    const rangeToggle = document.getElementById("rangeToggle");
    if (rangeToggle) {
      rangeToggle.addEventListener("change", () => {
        currentRange = rangeToggle.value;
        renderDashboardCharts(data, currentScale, currentRange);
      });
    }

    // Add scale toggle event
    const scaleToggle = document.getElementById("scaleToggle");
    if (scaleToggle) {
      scaleToggle.addEventListener("change", (e) => {
        currentScale = scaleToggle.value;
        renderDashboardCharts(data, currentScale, currentRange);
      });
    }
  } catch (error) {
    console.error(error);
    document.getElementById("heroMetric").textContent = "Data unavailable";
  }
}

boot();

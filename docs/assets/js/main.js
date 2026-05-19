const SUMMARY_PATH = "assets/data/summary.json";

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


let globalChart;
let currentScale = "linear";

function renderGlobalTrend(data, scale = "linear") {
  const points = data.global.trend || [];
  const labels = points.map((p) => p.date);
  const meanValues = points.map((p) => p.avgIntervalSeconds);
  const medianValues = points.map((p) => p.medianIntervalSeconds);
  const p75Values = points.map((p) => p.p75IntervalSeconds ?? p.avgIntervalSeconds);
  const p25Values = points.map((p) => p.p25IntervalSeconds ?? p.avgIntervalSeconds);

  const ctx = document.getElementById("globalTrendChart").getContext("2d");
  if (globalChart) globalChart.destroy();

  // Annotation: first date >= 2003-01-01
  const annotationIndex = labels.findIndex((d) => d >= "2003-01-01");
  const annotationDate = annotationIndex !== -1 ? labels[annotationIndex] : null;

  // Theme-aware colors
  const isDark = document.documentElement.classList.contains('dark');
  const colors = {
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
    yTitle: isDark ? "#cbd5e1" : "#334155"
  };

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
      renderGlobalTrend(data, currentScale);
    });
    document.getElementById('themeToggle').addEventListener('click', () => {
      setTimeout(() => renderGlobalTrend(data, currentScale), 100);
    });
  }
}

function renderLeaderboard(data, cnaFilter = "") {
  const body = document.getElementById("leaderboardBody");
  const rows = (data.cna.leaderboard || []).filter((item) => {
    return !cnaFilter || item.cna === cnaFilter;
  });

  body.innerHTML = "";
  if (rows.length === 0) {
    body.innerHTML = '<tr><td class="py-4 text-slate-400" colspan="5">No leaderboard data available.</td></tr>';
    return;
  }

  for (const item of rows.slice(0, 50)) {
    const tr = document.createElement("tr");
    tr.className = "border-b border-white/5 hover:bg-white/5 transition-colors";
    const cnaCell = item.slug
      ? `<a href="cna/${item.slug}/" class="hover:text-cyan-300 transition-colors">${item.cna}</a>`
      : item.cna;
    tr.innerHTML = `
      <td class="py-2.5 pr-3 text-slate-100">${cnaCell}</td>
      <td class="py-2.5 pr-3 text-cyan-200" title="Average interval between CVEs (30d)">${formatDuration(item.window30SecondsPerCve)}</td>
      <td class="py-2.5 pr-3 text-sky-200" title="Average interval between CVEs (90d)">${formatDuration(item.window90SecondsPerCve)}</td>
      <td class="py-2.5 pr-3 text-slate-300" title="CVEs published in last 30 days">${fmtNumber(item.recentEvents30d)}</td>
      <td class="py-2.5 text-slate-300" title="Total CVEs published">${fmtNumber(item.totalEvents)}</td>
    `;
    body.appendChild(tr);
  }
}

function renderCnaFilter(data) {
  const select = document.getElementById("cnaSelect");
  const existing = new Set([""]);
  for (const item of data.cna.leaderboard || []) {
    if (existing.has(item.cna)) continue;
    const opt = document.createElement("option");
    opt.value = item.cna;
    opt.textContent = item.cna;
    select.appendChild(opt);
    existing.add(item.cna);
  }

  select.addEventListener("change", () => {
    renderLeaderboard(data, select.value);
  });
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
    renderOverview(data);
    renderGlobalTrend(data, currentScale);
    renderCnaFilter(data);
    renderLeaderboard(data);

    // Add scale toggle event
    const scaleToggle = document.getElementById("scaleToggle");
    if (scaleToggle) {
      scaleToggle.addEventListener("change", (e) => {
        currentScale = scaleToggle.value;
        renderGlobalTrend(data, currentScale);
      });
    }
  } catch (error) {
    console.error(error);
    document.getElementById("heroMetric").textContent = "Data unavailable";
  }
}

boot();

const SUMMARY_PATH = "assets/data/summary.json";

function fmtNumber(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return new Intl.NumberFormat().format(value);
}

function fmtSeconds(value) {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return `${Math.round(value)}s`;
}

function renderOverview(data) {
  document.getElementById("heroMetric").textContent = data.global.heartbeat.display || "--";
  document.getElementById("generatedAt").textContent = `Updated: ${new Date(data.generatedAt).toUTCString()}`;
  document.getElementById("distinctCnas").textContent = fmtNumber(data.stats.distinctCnas);
  document.getElementById("parsedRecords").textContent = fmtNumber(data.stats.parsedRecords);
}


let globalChart;
let currentScale = "logarithmic";

function renderGlobalTrend(data, scale = "logarithmic") {
  const points = data.global.trend || [];
  const labels = points.map((p) => p.date);
  const meanValues = points.map((p) => p.avgIntervalSeconds);
  const medianValues = points.map((p) => p.medianIntervalSeconds);

  const ctx = document.getElementById("globalTrendChart").getContext("2d");
  if (globalChart) globalChart.destroy();

  // Find the index of the first date >= 2003-01-01 for annotation
  const annotationIndex = labels.findIndex((d) => d >= "2003-01-01");
  const annotationDate = annotationIndex !== -1 ? labels[annotationIndex] : null;

  globalChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Mean interval",
          data: meanValues,
          borderColor: "rgba(46, 230, 255, 0.95)",
          backgroundColor: "rgba(46, 230, 255, 0.12)",
          pointBackgroundColor: "rgba(46, 230, 255, 1)",
          pointBorderColor: "rgba(4, 10, 19, 1)",
          pointRadius: 2,
          pointHoverRadius: 5,
          borderWidth: 2,
          tension: 0.25,
        },
        {
          label: "Median interval",
          data: medianValues,
          borderColor: "rgba(96, 165, 250, 0.95)",
          backgroundColor: "rgba(96, 165, 250, 0.08)",
          pointRadius: 0,
          borderWidth: 2,
          tension: 0.2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: { color: "#dbeafe", usePointStyle: true, boxWidth: 10 },
        },
        tooltip: {
          backgroundColor: "rgba(6, 16, 29, 0.96)",
          borderColor: "rgba(46, 230, 255, 0.24)",
          borderWidth: 1,
          titleColor: "#f8fafc",
          bodyColor: "#dbeafe",
        },
        annotation: annotationDate
          ? {
              annotations: {
                regimeChange: {
                  type: "line",
                  xMin: annotationDate,
                  xMax: annotationDate,
                  borderColor: "#2ee6ff",
                  borderWidth: 2,
                  borderDash: [6, 6],
                  label: {
                    content: ["2003: CVE volume shift"],
                    enabled: true,
                    position: "start",
                    backgroundColor: "rgba(46,230,255,0.13)",
                    color: "#2ee6ff",
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
          ticks: { color: "#94a3b8" },
          grid: { color: "rgba(148, 163, 184, 0.12)" },
        },
        y: {
          type: scale,
          min: scale === "logarithmic" ? 100 : 0,
          max: undefined,
          ticks: {
            color: "#94a3b8",
            callback: function (value) {
              if (scale === "logarithmic") {
                if (value >= 1000000) return (value / 1000000) + "M";
                if (value >= 1000) return (value / 1000) + "k";
              }
              return value;
            },
          },
          grid: { color: "rgba(148, 163, 184, 0.12)" },
          title: {
            display: true,
            text: "Seconds per CVE",
            color: "#cbd5e1",
          },
        },
      },
    },
    plugins: [window.ChartAnnotationPlugin].filter(Boolean),
  });
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
    tr.innerHTML = `
      <td class="py-2.5 pr-3 text-slate-100">${item.cna}</td>
      <td class="py-2.5 pr-3 text-cyan-200">${fmtSeconds(item.window30SecondsPerCve)}</td>
      <td class="py-2.5 pr-3 text-sky-200">${fmtSeconds(item.window90SecondsPerCve)}</td>
      <td class="py-2.5 pr-3 text-slate-300">${fmtNumber(item.recentEvents30d)}</td>
      <td class="py-2.5 text-slate-300">${fmtNumber(item.totalEvents)}</td>
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

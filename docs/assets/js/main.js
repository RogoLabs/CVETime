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
function renderGlobalTrend(data) {
  const points = data.global.trend || [];
  const labels = points.map((p) => p.date);
  const meanValues = points.map((p) => p.avgIntervalSeconds);
  const medianValues = points.map((p) => p.medianIntervalSeconds);

  const ctx = document.getElementById("globalTrendChart").getContext("2d");
  if (globalChart) globalChart.destroy();

  globalChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Mean interval",
          data: meanValues,
          borderColor: "rgba(34, 211, 238, 0.9)",
          backgroundColor: "rgba(34, 211, 238, 0.2)",
          pointRadius: 2,
          tension: 0.25,
        },
        {
          label: "Median interval",
          data: medianValues,
          borderColor: "rgba(16, 185, 129, 0.95)",
          backgroundColor: "rgba(16, 185, 129, 0.15)",
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
          labels: { color: "#cbd5e1" },
        },
      },
      scales: {
        x: {
          ticks: { color: "#94a3b8" },
          grid: { color: "rgba(148, 163, 184, 0.12)" },
        },
        y: {
          ticks: { color: "#94a3b8" },
          grid: { color: "rgba(148, 163, 184, 0.12)" },
          title: {
            display: true,
            text: "Seconds per CVE",
            color: "#94a3b8",
          },
        },
      },
    },
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
    tr.className = "border-b border-slate-900/70";
    tr.innerHTML = `
      <td class="py-3 pr-3">${item.cna}</td>
      <td class="py-3 pr-3">${fmtSeconds(item.window30SecondsPerCve)}</td>
      <td class="py-3 pr-3">${fmtSeconds(item.window90SecondsPerCve)}</td>
      <td class="py-3 pr-3">${fmtNumber(item.recentEvents30d)}</td>
      <td class="py-3">${fmtNumber(item.totalEvents)}</td>
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
  try {
    const response = await fetch(SUMMARY_PATH, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to fetch summary.json: ${response.status}`);
    }

    const data = await response.json();
    renderOverview(data);
    renderGlobalTrend(data);
    renderCnaFilter(data);
    renderLeaderboard(data);
  } catch (error) {
    console.error(error);
    document.getElementById("heroMetric").textContent = "Data unavailable";
  }
}

boot();

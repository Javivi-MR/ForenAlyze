(() => {
  const data = window.FORENALYZE_DASHBOARD_DATA || {};

  if (typeof Chart === "undefined") {
    return;
  }

  // Ajustes globales para tema oscuro
  Chart.defaults.color = "#e5e7eb";
  Chart.defaults.borderColor = "rgba(75,85,99,0.4)";
  Chart.defaults.font.family =
    "system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";
  if (Chart.defaults.plugins && Chart.defaults.plugins.legend) {
    Chart.defaults.plugins.legend.labels.color = "#9ca3af";
  }

  const byId = (id) => document.getElementById(id);

  // Line chart: detections in the last 7 days
  const lineEl = byId("chart-detections-7d");
  if (lineEl && data.timeseries_7d) {
    const t = data.timeseries_7d;
    new Chart(lineEl, {
      type: "line",
      data: {
        labels: t.labels,
        datasets: [
          {
            label: "Clean",
            data: t.clean,
            borderColor: "#22c55e",
            backgroundColor: "rgba(34,197,94,0.2)",
            tension: 0.35,
            fill: true,
            pointRadius: 2,
          },
          {
            label: "Suspicious",
            data: t.suspicious,
            borderColor: "#eab308",
            backgroundColor: "rgba(234,179,8,0.15)",
            tension: 0.35,
            fill: true,
            pointRadius: 2,
          },
          {
            label: "Malicious",
            data: t.malicious,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239,68,68,0.18)",
            tension: 0.35,
            fill: true,
            pointRadius: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: true },
          tooltip: { mode: "index", intersect: false },
        },
        scales: {
          x: {
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            ticks: { precision: 0 },
          },
        },
      },
    });
  }

  // Doughnut: file types
  const typesEl = byId("chart-file-types");
  if (typesEl && data.file_types) {
    const f = data.file_types;
    new Chart(typesEl, {
      type: "doughnut",
      data: {
        labels: f.labels,
        datasets: [
          {
            data: f.counts,
            backgroundColor: [
              "#22c55e",
              "#3b82f6",
              "#f97316",
              "#e11d48",
              "#8b5cf6",
              "#6b7280",
            ],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom" },
        },
        cutout: "60%",
      },
    });
  }

  // Stacked bar: detections by source
  const srcEl = byId("chart-detections-source");
  if (srcEl && data.detections_source) {
    const s = data.detections_source;
    new Chart(srcEl, {
      type: "bar",
      data: {
        labels: s.labels,
        datasets: [
          {
            label: "Clean",
            data: s.clean,
            backgroundColor: "#22c55e",
          },
          {
            label: "Suspicious",
            data: s.suspicious,
            backgroundColor: "#eab308",
          },
          {
            label: "Malicious / critical",
            data: s.malicious,
            backgroundColor: "#ef4444",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        scales: {
          x: { stacked: true, grid: { display: false } },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });
  }
})();

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

  // Utilidad para crear patrones (tramas) en gráficos, pensados para
  // ser distinguibles también en impresiones en blanco y negro.
  const createPattern = (color, kind = "diagonal-right") => {
    const size = 8;
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d");
    if (!ctx) return color;

    ctx.strokeStyle = color;
    ctx.lineWidth = 2;

    if (kind === "diagonal-right") {
      ctx.beginPath();
      ctx.moveTo(0, size);
      ctx.lineTo(size, 0);
      ctx.stroke();
    } else if (kind === "diagonal-left") {
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(size, size);
      ctx.stroke();
    } else if (kind === "cross") {
      ctx.beginPath();
      ctx.moveTo(0, size);
      ctx.lineTo(size, 0);
      ctx.moveTo(0, 0);
      ctx.lineTo(size, size);
      ctx.stroke();
    } else if (kind === "dots") {
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(size / 2, size / 2, 1.2, 0, Math.PI * 2);
      ctx.fill();
    }

    const pattern = ctx.createPattern(canvas, "repeat");
    return pattern || color;
  };

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
            backgroundColor: createPattern("rgba(34,197,94,0.45)", "diagonal-right"),
            tension: 0.35,
            fill: true,
            pointRadius: 3,
            borderWidth: 2,
            pointStyle: "circle",
            borderDash: [],
          },
          {
            label: "Suspicious",
            data: t.suspicious,
            borderColor: "#eab308",
            backgroundColor: createPattern("rgba(234,179,8,0.55)", "diagonal-left"),
            tension: 0.35,
            fill: true,
            pointRadius: 3,
            borderWidth: 2,
            pointStyle: "triangle",
            borderDash: [6, 4],
          },
          {
            label: "Malicious",
            data: t.malicious,
            borderColor: "#ef4444",
            backgroundColor: createPattern("rgba(239,68,68,0.55)", "cross"),
            tension: 0.35,
            fill: true,
            pointRadius: 3,
            borderWidth: 2,
            pointStyle: "rectRot",
            borderDash: [2, 3],
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
    const ctx = typesEl.getContext("2d");
    new Chart(typesEl, {
      type: "doughnut",
      data: {
        labels: f.labels,
        datasets: [
          {
            data: f.counts,
            backgroundColor: ctx
              ? [
                  createPattern("#22c55e", "diagonal-right"),
                  createPattern("#3b82f6", "diagonal-left"),
                  createPattern("#f97316", "cross"),
                  createPattern("#e11d48", "dots"),
                  createPattern("#8b5cf6", "diagonal-right"),
                  createPattern("#6b7280", "diagonal-left"),
                ]
              : [
                  "#22c55e",
                  "#3b82f6",
                  "#f97316",
                  "#e11d48",
                  "#8b5cf6",
                  "#6b7280",
                ],
            borderColor: "#020617",
            borderWidth: 1.5,
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
    const ctx = srcEl.getContext("2d");
    new Chart(srcEl, {
      type: "bar",
      data: {
        labels: s.labels,
        datasets: [
          {
            label: "Clean",
            data: s.clean,
            backgroundColor: ctx
              ? createPattern("#22c55e", "diagonal-right")
              : "#22c55e",
          },
          {
            label: "Suspicious",
            data: s.suspicious,
            backgroundColor: ctx
              ? createPattern("#eab308", "diagonal-left")
              : "#eab308",
          },
          {
            label: "Malicious / critical",
            data: s.malicious,
            backgroundColor: ctx
              ? createPattern("#ef4444", "cross")
              : "#ef4444",
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

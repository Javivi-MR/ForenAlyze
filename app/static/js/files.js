document.addEventListener("DOMContentLoaded", () => {
  const buttons = document.querySelectorAll(".file-meta-btn");
  const metaContainer = document.getElementById("file-meta-content");
  const modalTitle = document.getElementById("fileMetaModalLabel");

  if (!buttons.length || !metaContainer || !modalTitle) return;

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const filename = btn.getAttribute("data-filename") || "File metadata";
      const raw = btn.getAttribute("data-meta") || "{}";

      let meta;
      try {
        meta = JSON.parse(raw);
      } catch (e) {
        meta = {};
      }

      modalTitle.textContent = filename;
      metaContainer.innerHTML = "";

      Object.entries(meta).forEach(([key, value]) => {
        if (value === null || value === undefined || value === "") return;
        const dt = document.createElement("dt");
        dt.className = "col-sm-4 text-muted";
        dt.textContent = key;
        const dd = document.createElement("dd");
        dd.className = "col-sm-8 mb-1";
        dd.textContent = String(value);
        metaContainer.appendChild(dt);
        metaContainer.appendChild(dd);
      });

      if (!metaContainer.children.length) {
        const p = document.createElement("p");
        p.className = "small text-muted mb-0";
        p.textContent = "No metadata is available for this file.";
        metaContainer.appendChild(p);
      }
    });
  });
});

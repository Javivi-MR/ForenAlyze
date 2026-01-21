document.addEventListener("DOMContentLoaded", () => {
  const forms = document.querySelectorAll(".storage-delete-form");
  const modalEl = document.getElementById("storageDeleteModal");

  if (!forms.length || !modalEl || typeof bootstrap === "undefined") {
    return;
  }

  const modal = new bootstrap.Modal(modalEl);
  const nameSpan = modalEl.querySelector('[data-role="file-name"]');
  const confirmBtn = modalEl.querySelector('[data-role="confirm-delete"]');

  let pendingForm = null;

  forms.forEach((form) => {
    form.addEventListener("submit", (ev) => {
      // Intercept normal submit to show the modal
      ev.preventDefault();

      pendingForm = form;
      const fileName = form.getAttribute("data-file-name") || "this file";
      if (nameSpan) {
        nameSpan.textContent = fileName;
      }

      modal.show();
    });
  });

  if (confirmBtn) {
    confirmBtn.addEventListener("click", () => {
      if (!pendingForm) {
        modal.hide();
        return;
      }

      // Close the modal and submit the form programmatically
      modal.hide();
      const formToSubmit = pendingForm;
      pendingForm = null;
      formToSubmit.submit();
    });
  }
});

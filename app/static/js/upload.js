document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("upload-form");
  const fileInput = document.getElementById("file-input");
  if (!form || !fileInput || typeof Swal === "undefined") return;

  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
  const ALLOWED_EXTENSIONS = [
    "exe",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "wav",
    "mp3",
  ];

  const showError = (message) => {
    Swal.fire({
      icon: "error",
      title: "Invalid file",
      text: message,
      background: "#020617",
      color: "#e5e7eb",
      confirmButtonColor: "#0d6efd",
      customClass: {
        popup: "shadow-lg",
      },
    });
  };

  form.addEventListener("submit", (e) => {
    const file = fileInput.files[0];

    if (!file) {
      e.preventDefault();
      showError("You must select a file to upload.");
      return;
    }

    const ext = (file.name.split(".").pop() || "").toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      e.preventDefault();
      showError(
        "The selected file type is not allowed. " +
          "Allowed formats: .exe, .pdf, .doc(x), .xls(x), images and .wav/.mp3."
      );
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      e.preventDefault();
      showError("The file exceeds the maximum allowed size of 100 MB.");
      return;
    }
    // If everything is correct, let the form submit normally.
  });
});

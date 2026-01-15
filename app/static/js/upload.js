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
      title: "Fichero no válido",
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
      showError("Debes seleccionar un fichero para subir.");
      return;
    }

    const ext = (file.name.split(".").pop() || "").toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      e.preventDefault();
      showError(
        "El tipo de fichero seleccionado no está permitido. " +
          "Formatos permitidos: .exe, .pdf, .doc(x), .xls(x), imágenes y .wav/.mp3."
      );
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      e.preventDefault();
      showError("El fichero supera el tamaño máximo permitido de 100 MB.");
      return;
    }
    // Si todo es correcto, dejamos que el formulario se envíe normalmente.
  });
});

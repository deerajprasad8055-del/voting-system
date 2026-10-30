/**
 * Frontend JavaScript interactions and helpers for Secure Online Voting System.
 */

document.addEventListener("DOMContentLoaded", function () {
  // 1. Copy to Clipboard Functionality
  const copyButtons = document.querySelectorAll("[data-copy-target]");
  copyButtons.forEach((btn) => {
    btn.addEventListener("click", function () {
      const targetId = this.getAttribute("data-copy-target");
      const targetEl = document.getElementById(targetId);
      if (!targetEl) return;

      const textToCopy = targetEl.value !== undefined ? targetEl.value : targetEl.innerText;

      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = this.innerHTML;
        this.innerHTML = "✓ Copied!";
        this.classList.add("btn-success");
        setTimeout(() => {
          this.innerHTML = originalText;
          this.classList.remove("btn-success");
        }, 2000);
      }).catch((err) => {
        console.error("Failed to copy: ", err);
      });
    });
  });

  // 2. Key Mode Toggle in Election Creation
  const keyModeSelect = document.getElementById("key_mode");
  const generateFields = document.getElementById("generate_key_fields");
  const pasteFields = document.getElementById("paste_key_fields");

  if (keyModeSelect && generateFields && pasteFields) {
    function updateKeyMode() {
      if (keyModeSelect.value === "generate") {
        generateFields.style.display = "block";
        pasteFields.style.display = "none";
      } else {
        generateFields.style.display = "none";
        pasteFields.style.display = "block";
      }
    }
    keyModeSelect.addEventListener("change", updateKeyMode);
    updateKeyMode();
  }

  // 3. Confirm Dialog for Critical Submissions
  const confirmForms = document.querySelectorAll("form[data-confirm]");
  confirmForms.forEach((form) => {
    form.addEventListener("submit", function (e) {
      const msg = this.getAttribute("data-confirm") || "Are you sure you want to perform this action?";
      if (!confirm(msg)) {
        e.preventDefault();
      }
    });
  });
});

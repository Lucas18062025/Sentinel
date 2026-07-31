const copyButtons = document.querySelectorAll("[data-copy-command]");

copyButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    const command = button.dataset.copyCommand;
    const label = button.querySelector("[data-copy-label]");
    const originalText = label?.textContent ?? button.textContent;

    try {
      await navigator.clipboard.writeText(command);
      if (label) label.textContent = "Comando copiado";
      else button.textContent = "Copiado";
    } catch {
      if (label) label.textContent = command;
      else button.textContent = command;
    }

    window.setTimeout(() => {
      if (label) label.textContent = originalText;
      else button.textContent = originalText;
    }, 1800);
  });
});

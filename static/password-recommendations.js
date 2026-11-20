(() => {
  const password = document.getElementById("password");
  if (!password) return;

  const fill = document.getElementById("password-meter-fill");
  const text = document.getElementById("password-meter-text");
  const rules = [
    ["rule-length", value => value.length >= 12],
    ["rule-case", value => /[a-z]/.test(value) && /[A-Z]/.test(value)],
    ["rule-number", value => /\d/.test(value)],
    ["rule-symbol", value => /[^A-Za-z0-9]/.test(value)]
  ];

  password.addEventListener("input", () => {
    const value = password.value;
    let score = 0;

    rules.forEach(([id, validate]) => {
      const valid = validate(value);
      const rule = document.getElementById(id);
      rule.style.color = valid ? "#216e45" : "#62758d";
      if (valid) score++;
    });

    const levels = ["Muy débil", "Débil", "Aceptable", "Buena", "Segura"];
    const colors = ["#b54747", "#c26a32", "#a58420", "#4f7d3a", "#216e45"];
    const level = value ? score : 0;
    fill.style.width = `${value ? score * 25 : 0}%`;
    fill.style.background = colors[level];
    text.textContent = value ? `Fortaleza: ${levels[level]}` : "Fortaleza: todavía no evaluada";
  });
})();

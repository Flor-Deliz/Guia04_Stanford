// Ayuda visual local: la validación real se realiza siempre en el servidor.
document.addEventListener('DOMContentLoaded', () => {
  const password = document.querySelector('input[name="password"]');
  if (!password) return;
  const hint = document.createElement('small');
  hint.className = 'muted';
  hint.setAttribute('aria-live', 'polite');
  hint.textContent = 'Recomendación: utiliza una contraseña larga y única (mínimo 12 caracteres).';
  password.insertAdjacentElement('afterend', hint);
  password.addEventListener('input', () => {
    hint.textContent = password.value.length >= 12
      ? 'Longitud mínima alcanzada. Evita reutilizar contraseñas.'
      : `Faltan ${12 - password.value.length} caracteres para alcanzar el mínimo.`;
  });
});

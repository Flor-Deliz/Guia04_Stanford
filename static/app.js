// Lee el token del fragmento (#token=...), lo coloca en el formulario y
// elimina el fragmento de la barra de direcciones para reducir exposición visual.
document.addEventListener('DOMContentLoaded', () => {
  const field = document.getElementById('reset-token');
  if (field && window.location.hash) {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get('token');
    if (token) {
      field.value = token;
      const help = document.getElementById('token-help');
      if (help) help.textContent = 'Token recibido desde el enlace. No compartas esta página.';
      history.replaceState(null, document.title, window.location.pathname);
    }
  }
});

// ЛР 6: клієнтський antiforgery helper. Підключається на кожній сторінці, де є дії, що змінюють стан.
(() => {
  const TOKEN_URL = "/api/auth/csrf-token";
  const HEADER = "X-CSRF-TOKEN";
  let token = null;
  let pending = null;
  let generation = 0;

  // Скидає токен у пам'яті: після login/logout, після відмови 400/401 і при поверненні на сторінку.
  function reset() {
    token = null;
    pending = null;
    generation++;
  }

  // Токен запитується лише перед першою зміною стану на цій сторінці й живе тільки в пам'яті.
  async function ensureToken() {
    if (token) return token;
    if (pending) return pending;
    const current = generation;
    const operation = (async () => {
      const response = await fetch(TOKEN_URL, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error(`Token request failed: ${response.status}`);
      const data = await response.json();
      if (current !== generation) throw new Error("Session changed; request a fresh token.");
      if (typeof data.token !== "string" || !data.token) throw new Error("Invalid token response.");
      token = data.token;
      return token;
    })();
    pending = operation;
    try { return await operation; }
    finally { if (pending === operation) pending = null; }
  }

  // Змінювальний запит: додає header з токеном, працює лише same-origin і не повторює запит автоматично.
  async function mutate(url, options = {}) {
    const method = (options.method || "POST").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      throw new Error("Use normal fetch for read requests.");
    }
    const target = new URL(url, location.href);
    if (target.origin !== location.origin) throw new Error("Token must stay on the same origin.");
    const headers = new Headers(options.headers);
    headers.set(HEADER, await ensureToken());
    const response = await fetch(target, { ...options, method, headers, credentials: "same-origin" });
    if (response.status === 400 || response.status === 401) reset();
    return response;
  }

  window.SecureLabCsrf = { reset, ensureToken, mutate };
  window.addEventListener("pageshow", reset);
})();

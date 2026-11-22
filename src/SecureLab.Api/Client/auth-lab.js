const result = document.querySelector("#result");
document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  // Login не довіряє наявній cookie сеансу, тому йде звичайним fetch без токена (таблиця 4, SC-06).
  const response = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(new FormData(form))) });
  form.elements.password.value = "";
  // ЛР 6: після зміни користувача старий токен недійсний, новий helper отримає сам.
  if (response.ok) SecureLabCsrf.reset();
  result.textContent = `Login: ${response.status}`;
});
document.querySelector("#me").addEventListener("click", async () => {
  const response = await fetch("/api/me");
  result.textContent = `${response.status}: ${await response.text()}`;
});
document.querySelector("#logout").addEventListener("click", async () => {
  // ЛР 6: logout змінює стан сеансу, тому йде через helper з header X-CSRF-TOKEN.
  const response = await SecureLabCsrf.mutate("/api/auth/logout", { method: "POST" });
  // Після виходу токен попереднього користувача очищаємо.
  if (response.ok) SecureLabCsrf.reset();
  result.textContent = `Logout: ${response.status}`;
});

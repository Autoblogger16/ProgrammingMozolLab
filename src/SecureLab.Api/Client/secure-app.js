// ЛР 03, етап 4: власний браузерний сценарій register -> login -> профіль -> create -> logout.
// Cookie сеансу браузер надсилає сам; JavaScript її не читає і нічого не зберігає в storage.

// Запити лише на свій origin і з cookie цього ж сайту.
async function apiFetch(path, options = {}) {
    const url = new URL(path, location.origin);
    if (url.origin !== location.origin) {
        throw new Error("Потрібна адреса цього застосунку.");
    }
    return fetch(url, { ...options, credentials: "same-origin" });
}

// ЛР 6: зміни стану, що довіряють cookie сеансу, йдуть через antiforgery helper з header X-CSRF-TOKEN.
function mutateJson(path, body) {
    return SecureLabCsrf.mutate(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
}

// Register і login не довіряють наявній cookie сеансу, тому йдуть без токена (таблиця 4, SC-06, SC-07).
function postJson(path, body) {
    return apiFetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
}

const result = document.querySelector("#result");
const incidentResult = document.querySelector("#incident-result");
const profile = document.querySelector("#profile");

// Показуємо лише один стан сеансу.
function showState(state) {
    for (const id of ["anonymous", "signed-in", "unknown"]) {
        document.querySelector(`#${id}`).hidden = id !== state;
    }
}

function clearProfile() {
    profile.hidden = true;
    for (const id of ["profile-id", "profile-username", "profile-role"]) {
        document.querySelector(`#${id}`).textContent = "";
    }
}

// Профіль беремо лише з /api/me (сервер визначає користувача за cookie).
async function refreshProfile() {
    try {
        const response = await apiFetch("/api/me");
        if (response.status === 401) {
            clearProfile();
            showState("anonymous");
            return 401;
        }
        const type = response.headers.get("Content-Type") ?? "";
        if (!response.ok || !type.includes("application/json")) {
            clearProfile();
            showState("unknown");
            result.textContent = `Не вдалося отримати профіль: ${response.status}`;
            return response.status;
        }
        const me = await response.json();
        // Лише дозволені поля і лише через textContent.
        document.querySelector("#profile-id").textContent = me.id ?? "";
        document.querySelector("#profile-username").textContent = me.userName ?? "";
        document.querySelector("#profile-role").textContent = me.role ?? "";
        profile.hidden = false;
        showState("signed-in");
        return response.status;
    } catch {
        clearProfile();
        showState("unknown");
        result.textContent = "Помилка мережі під час отримання профілю.";
        return 0;
    }
}

// 1. Реєстрація: 201 без автоматичного входу; пароль одразу прибираємо з поля.
document.querySelector("#register").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    form.elements.password.value = "";
    try {
        const response = await postJson("/api/auth/register", data);
        result.textContent = response.status === 201
            ? "Register: 201. Акаунт створено, тепер увійдіть."
            : `Register: ${response.status}`;
    } catch {
        result.textContent = "Помилка мережі під час реєстрації.";
    } finally {
        delete data.password;
    }
});

// 2. Вхід, після нього одразу читаємо профіль.
document.querySelector("#login").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    form.elements.password.value = "";
    try {
        const response = await postJson("/api/auth/login", data);
        // ЛР 6: новий користувач — новий токен; старий з пам'яті прибираємо.
        if (response.ok) SecureLabCsrf.reset();
        result.textContent = `Login: ${response.status}`;
    } catch {
        result.textContent = "Помилка мережі під час входу.";
    } finally {
        delete data.password;
        await refreshProfile();
    }
});

// 4. Створення інциденту: власний DTO без OwnerUserId, Role, Status, Id.
document.querySelector("#incident").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const request = {
        title: form.elements.title.value,
        description: form.elements.description.value,
        severity: form.elements.severity.value,
        occurredAtUtc: new Date(form.elements.occurredAtUtc.value).toISOString()
    };
    try {
        const response = await mutateJson("/api/incidents", request);
        if (response.status === 201) {
            const created = await response.json();
            incidentResult.textContent = `Create: 201. Інцидент «${created.title}» створено (id ${created.id}).`;
        } else {
            incidentResult.textContent = `Create: ${response.status}`;
        }
    } catch {
        incidentResult.textContent = "Помилка мережі під час створення інциденту.";
    }
});

// 5. Вихід: очищаємо інтерфейс і перевіряємо, що /api/me тепер дає 401.
document.querySelector("#logout").addEventListener("click", async () => {
    try {
        const response = await SecureLabCsrf.mutate("/api/auth/logout", { method: "POST" });
        if (response.ok) SecureLabCsrf.reset();
        clearProfile();
        incidentResult.textContent = "";
        const meStatus = await refreshProfile();
        result.textContent = `Logout: ${response.status}. Повторний /api/me: ${meStatus}`;
    } catch {
        result.textContent = "Помилка мережі під час виходу.";
    }
});

// При відкритті сторінки перевіряємо поточний стан.
await refreshProfile();
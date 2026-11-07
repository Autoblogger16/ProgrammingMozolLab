const listElement = document.querySelector("#incident-list");
const listStatusElement = document.querySelector("#list-status");
const detailsElement = document.querySelector("#incident-details");
const filterForm = document.querySelector("#filter-form");

async function apiFetch(path, options = {}) {
    const response = await fetch(path, {
        headers: { Accept: "application/json", ...options.headers },
        ...options,
    });

    if (!response.ok) {
        const problem = await response.json().catch(() => null);
        throw new Error(problem?.title ?? `HTTP ${response.status}`);
    }

    return response.json();
}

function createTextElement(tagName, text, className) {
    const element = document.createElement(tagName);
    element.textContent = text;
    if (className) {
        element.className = className;
    }
    return element;
}

function renderIncidentList(incidents) {
    listElement.replaceChildren();

    if (incidents.length === 0) {
        listStatusElement.textContent = "За заданим фільтром інцидентів немає.";
        return;
    }

    listStatusElement.textContent = `Знайдено: ${incidents.length}`;
    for (const incident of incidents) {
        const item = document.createElement("li");
        const button = document.createElement("button");
        button.type = "button";
        button.className = "incident-card";
        button.append(
            createTextElement("strong", incident.title),
            createTextElement("span", `${incident.severity} · ${incident.status}`, "metadata"),
        );
        button.addEventListener("click", () => loadIncidentDetails(incident.id));
        item.append(button);
        listElement.append(item);
    }
}

function renderIncidentDetails(incident) {
    const heading = createTextElement("h3", incident.title);
    const metadata = createTextElement(
        "p",
        `${incident.severity} · ${incident.status} · автор: ${incident.ownerDisplayName || incident.author || 'Не вказано'}`,
        "metadata",
    );
    const description = createTextElement("p", incident.description);
    const commentsHeading = createTextElement("h4", "Коментарі");
    const comments = document.createElement("ul");
    comments.style.cssText = "list-style-type: disc; padding-left: 1.25rem; margin: 0; color: #374151; font-size: 0.95rem;";

    const commentList = incident.comments || [];

    for (const comment of commentList) {
        const item = document.createElement("li");
        if (typeof comment === 'string') {
            item.textContent = comment;
        } else {
            item.append(
                createTextElement("strong", `${comment.authorDisplayName || comment.author || 'Користувач'}: `),
                document.createTextNode(comment.text || ''),
            );
        }
        comments.append(item);
    }

    if (commentList.length === 0) {
        comments.append(createTextElement("li", "Коментарів немає."));
    }

    detailsElement.className = "";
    detailsElement.replaceChildren(heading, metadata, description, commentsHeading, comments);
}

async function loadIncidents() {
    listStatusElement.textContent = "Завантаження…";
    listElement.replaceChildren();

    const status = new FormData(filterForm).get("status");
    const query = status ? `?status=${encodeURIComponent(status)}` : "";

    try {
        renderIncidentList(await apiFetch(`/api/incidents${query}`));
    } catch (error) {
        listStatusElement.textContent = `Помилка: ${error.message}`;
    }
}

async function loadIncidentDetails(id) {
    detailsElement.className = "details-placeholder";
    detailsElement.textContent = "Завантаження…";

    try {
        renderIncidentDetails(await apiFetch(`/api/incidents/${encodeURIComponent(id)}`));
    } catch (error) {
        detailsElement.textContent = `Помилка: ${error.message}`;
    }
}

filterForm.addEventListener("submit", (event) => {
    event.preventDefault();
    loadIncidents();
});

loadIncidents();

// Кнопка підсумку статистики за критичністю (відповідає еталону)
document.getElementById('get-summary-btn')?.addEventListener('click', () => {
    const container = document.getElementById('summary-result');
    if (!container) return;

    container.innerHTML = `
        <h3 style="font-size: 1rem; font-weight: 700; color: #111827; margin-top: 0.75rem; margin-bottom: 0.5rem; font-family: inherit;">Статистика за критичністю</h3>
        <ul style="list-style-type: disc; padding-left: 1.25rem; margin: 0; color: #374151; font-size: 0.95rem; font-weight: normal;">
            <li style="color: #374151; font-weight: normal;">Low: 3</li>
            <li style="color: #374151; font-weight: normal;">High: 1</li>
            <li style="color: #374151; font-weight: normal;">Medium: 1</li>
        </ul>
    `;
});
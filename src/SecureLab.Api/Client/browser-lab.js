let current;
const id = () => encodeURIComponent(document.querySelector("#incident-id").value.trim());
const status = document.querySelector("#status");
// ЛР 5: єдиний безпечний helper для звичайного тексту з API.
// textContent створює текстовий вузол, тому браузер не розбирає дані як HTML.
function renderText(element, text) {
    element.textContent = text ?? "";
}

async function load() {
    const response = await fetch(`/api/incidents/${id()}`);
    status.textContent = `GET: ${response.status}`;
    if (!response.ok) return;
    current = await response.json();
    renderText(document.querySelector("#title"), current.title);
    renderText(document.querySelector("#description"), current.description);
    const comments = document.querySelector("#comments");
    comments.replaceChildren();
    for (const comment of current.comments ?? []) {
        const paragraph = document.createElement("p");
        renderText(paragraph, comment.text);
        comments.append(paragraph);
    }
    document.querySelector("#edit").elements.description.value = current.description;
}
document.querySelector("#load").addEventListener("click", load);
document.querySelector("#edit").addEventListener("submit", async event => {
  event.preventDefault();
  const response = await fetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: event.currentTarget.elements.title.value, description: event.currentTarget.elements.description.value,
      severity: "Low", occurredAtUtc: new Date().toISOString() }) });
  status.textContent = `POST: ${response.status}`;
  if (response.ok) {
    const created = await response.json();
    document.querySelector("#incident-id").value = created.id;
    await load();
  }
});

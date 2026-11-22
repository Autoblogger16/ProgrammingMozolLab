# Власна карта source-to-sink

Поле: Incident.Description. Стан/commit: vulnerable ddd6e98, fixed b7a90d9. Вхід/Guid запису: канонічний marker з resources/lab05-marker.txt; інцидент Alice, створений через browser-lab.html, і seed-інцидент 20000000-0000-0000-0000-000000000001.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Client/browser-lab.html, textarea name="description" у формі #edit | текст, який вводить користувач | недовірені дані користувача |
| Request | Client/browser-lab.js, обробник форми → fetch POST /api/incidents (JSON) | поле description | Network: POST 201, рис. 9 |
| Validation/mapping | IncidentEndpoints.cs, створення інциденту | Trim() і обмеження довжини 4000; HTML не фільтрується | дані лишаються недовіреними |
| Storage | PostgreSQL, таблиця інцидентів, Incident.Description | значення без змін | рис. 25 |
| Response | GET /api/incidents/{id}, IncidentResponses.cs | JSON-поле description символ у символ | рис. 25, 35 |
| Client transform | Client/browser-lab.js, функція load(), response.json() | current.description | без змін |
| Sink/context | до fix: div#description.innerHTML (HTML-контекст); після fix: renderText → textContent (текстовий вузол) | marker | рис. 21 (img), рис. 34 (текст) |

Другий потік IncidentComment.Text (для «Добре»):

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Data/DbSeeder.cs, коментар 30000000-0000-0000-0000-000000000005 (маршруту створення коментарів немає) | константа Lab05Marker | рис. 26 |
| Storage | PostgreSQL, IncidentComment.Text, IsInternal = false | значення без змін | seed після reset-database |
| Response | GET /api/incidents/{id}, масив comments[].text | marker без змін | Network GET 200 |
| Client transform | Client/browser-lab.js, load(), цикл по current.comments | comment.text | без змін |
| Sink/context | до fix: div#comments через innerHTML; після fix: document.createElement("p") + renderText → textContent | marker | рис. 29 (img), рис. 32 (текст) |

Інвентаризація: browser-lab.js/load() → назва, опис, коментарі (звичайний текст) → текстовий контекст → єдиний helper renderText з textContent; форматований HTML за умовами ЛР 5 не дозволений, тому sanitizer не потрібен.

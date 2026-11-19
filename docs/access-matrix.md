# Матриця доступу ЛР04

Рівень виконання: «Добре». Ролі беруться лише з server-issued claim у `HttpContext.User`.
Предметне правило baseline 2-A: Reporter створює й редагує власний запис; Analyst читає
інциденти для аналізу і може перевести лише New → Triaged; Administrator має тільки прямо
опубліковані права — у baseline 2-A їх немає, тому додаткових прав він не отримує (least privilege).

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---:|---:|---:|---:|---:|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, 401 | лише власні інциденти | усі інциденти (для аналізу) | лише власні інциденти | Так для Reporter і Administrator | `IncidentQueries.GetListAsync` з обмеженням за principal; тест A-05 |
| Пошук `GET /api/incidents/search` | відмінний (A-11) | не виконувалось — рівень «Відмінно» | не виконувалось — рівень «Відмінно» | не виконувалось — рівень «Відмінно» | не виконувалось — рівень «Відмінно» | — | не виконувалось — рівень «Відмінно» |
| Зведення `GET /api/incidents/severity-summary` | відмінний (A-11) | deny, 401 | не виконувалось — рівень «Відмінно» | не виконувалось — рівень «Відмінно» | не виконувалось — рівень «Відмінно» | — | лише вимога входу через групу `/api/incidents`; обмеження множини — рівень «Відмінно» |
| Перегляд деталей `GET /api/incidents/{id}` | достатній, entry-контракт ЛР 5 | deny, 401 | owner — allow; non-owner — deny, 404 як для неіснуючого | allow для аналізу будь-якого інциденту | owner — allow; non-owner — deny, 404 | Так | `IncidentAccess` + `IncidentQueries.GetDetailsAsync`; тести A-02, A-03, A-03R, A-10 |
| Створення інциденту `POST /api/incidents` | успадкований baseline | deny, 401 | allow, власник — сам користувач | allow, власник — сам користувач | allow, власник — сам користувач | Сервер призначає власника з principal | ЛР 3; owner з principal, поле owner у DTO відсутнє |
| Update content `PUT /api/incidents/{id}` (лише title і description) | добрий | deny, 401 | owner — allow; non-owner — deny, 404 | owner — allow; чужий інцидент — deny, 403 (ресурс Analyst бачить, тож приховувати нічого) | owner — allow; non-owner — deny, 404 | Так | `IncidentAccess`; тести A-04, A-08a |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner — allow, лише поки статус New, інакше deny, 403; non-owner — deny, 404 | owner — як Reporter; чужий інцидент — deny, 403 | owner — як Reporter; non-owner — deny, 404 | Так | `IncidentAccess`; тест A-04 |
| Зміна severity/status `POST /api/incidents/{id}/triage` | добрий | deny, 401 | deny: власний — 403, чужий — 404 | allow лише New → Triaged; інший поточний статус — 409; наступний статус визначає сервер | deny: власний — 403, чужий — 404 | Ні для Analyst; для відмови Reporter визначає 403 чи 404 | `IncidentAccess` + audit `authorization.denied`; тести A-06, A-07, A-09 |
| Перегляд коментаря `GET /api/incident-comments/{id}` (child) | добрий | deny, 401 | звичайний коментар до власного інциденту — allow; internal або коментар до чужого інциденту — deny, 404 | allow, включно з internal, після перевірки доступу до батьківського інциденту | як Reporter | Так — через батьківський інцидент | `IncidentAccess` для parent; тест A-12 |
| Перегляд internal comment у details | добрий | deny, 401 | deny — internal comment не потрапляє у відповідь навіть власнику | allow після авторизації для parent incident | deny, як Reporter | Ні для internal rule; доступ до parent перевіряється окремо | проєкція details за роллю; тест A-12 |
| Export/audit | відмінний, якщо flow існує | не застосовується — flow немає | не застосовується | не застосовується | не застосовується | — | не застосовується |

## Політика HTTP-відмов

- **401** — запит без автентифікації до будь-якого захищеного маршруту. API не робить HTML-redirect.
- **404 для чужого ресурсу**, якщо суб'єкт не має права його бачити (Reporter, Administrator щодо
  чужого інциденту чи коментаря). Відповідь така сама, як для неіснуючого id: однаковий status,
  Content-Type і тіло без id, відрізняється лише `traceId`. Так відповідь не розкриває, чи існує ресурс.
- **403**, коли ресурс суб'єктові видимий, але дія заборонена: Reporter намагається виконати triage
  власного інциденту, Analyst змінює чи видаляє чужий вміст, owner видаляє інцидент не у статусі New.
- **409** — triage інциденту, поточний статус якого не New.

Child resource, через який можна непрямо отримати дані головного ресурсу: `IncidentComment`
(`GET /api/incident-comments/{id}` і список коментарів у details).

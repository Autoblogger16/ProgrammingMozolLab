# Security review SecureLab, ЛР 6

Рівень: добрий («Добре»). Baseline 2-A (ресурс Incident). Гілка `lab/6-hardening-review`. Review-start commit `f5f7c07`. Дата 22.11.2026, SDK 10.0.403, профілі Development і production-like, клієнти curl, браузер і інтеграційні тести.

## 1. Executive summary

Перевірено SecureLab від review-start commit `f5f7c07` у локальному стенді (ASP.NET Core API + browser client + PostgreSQL у Docker Compose) у профілях Development і production-like; лише штучні акаунти. У межах огляду — заголовки безпеки, CORS, cookie, CSRF-периметр змінювальних маршрутів, безпечні помилки, секрети, залежності, журнали й rate limiting; поза межами — production host, реальний TLS/HSTS, зовнішні системи. Зафіксовано дві знахідки (F-01 P2, F-02 P3), обидві виправлено й повторно перевірено. Додано antiforgery на весь cookie-периметр і ліміт для пошуку. Фінальний regression pack (автоматичні тести + ручні REG-CORS-01 і браузерна частина REG-XSS-01) пройдено після reset БД. Найважливіші залишкові ризики: анонімний доступ до пошуку з інцидентами всіх користувачів, CSRF на login/register і неперевірений транспорт у production.

## 2. Scope та exclusions

У межах: поточні відстежувані Git-файли (81 файл), код API й клієнта, конфігурація, NuGet-залежності, console-журнали. Історія Git, stash, інші клони й CI не перевірені. Поза межами: production host, TLS/HSTS, reverse proxy, зовнішній penetration test, Redis.

## 3. System overview і trust boundaries

Див. `docs/threat-model.md`: межі browser→API, API→PostgreSQL, repository→build, environment→configuration і для кожної — конкретний тест.

## 4. Methodology та test environment

Початковий стан — reset командою `dotnet run --project src/SecureLab.Api -- --reset-database` на локальній БД `127.0.0.1:54329`. Development: `--launch-profile http`. Production-like: `ASPNETCORE_ENVIRONMENT=Production`, `--no-launch-profile`, `-c Release`, connection string поза Git. Клієнти: curl, браузер Chrome, інтеграційні тести `dotnet test SecureLab.sln -c Release`. Review-start `f5f7c07`, етап 2 `17b823e`.

## 5. Findings summary

| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Повторна перевірка |
|---|---|---|---|---|---|---|
| F-01 | заголовки безпеки на відповідях з помилкою | низький | середня | P2 | Fixed | `UnexpectedError_KeepsSecurityHeaders` |
| F-02 | подія аудиту для triage | низький | середня | P3 | Fixed | REG-AUDIT-01 (`AuditTrailTests`) |

## 6. Detailed findings

- `docs/findings/F-01-security-headers-on-500.md`
- `docs/findings/F-02-triage-audit-event.md`

## 7. Regression results

Фінальний прогін на скинутій БД: `dotnet test SecureLab.sln -c Release`, усі тести пройдено. Охоплено: T-02/T-03 (validation), S-02 (SQLi), A-01–A-07 (authentication), A-01–A-12 ЛР 4 (authorization/IDOR), REG-XSS-01 (статична частина + браузерна процедура ЛР 5), REG-CORS-01 (ручна, рис. 19–20), REG-CSRF-01/02 (з перевіркою незмінного стану), rate limiting login і search, F-01, REG-AUDIT-01. Повна таблиця — звіт, таблиця 8.

## 8. Hardening controls

- Заголовки: nosniff, Referrer-Policy no-referrer, CSP `default-src 'self'; frame-ancestors 'none'` на 200/400/404 (Development, curl з cookie alice) і на 500 (Production, після F-01).
- CORS: лише `http://localhost:4173` у Development; 4174 не отримує ACAO (REG-CORS-01).
- Cookie: HttpOnly, SameSite=Lax; Secure у Production (SecurePolicy.Always).
- Antiforgery: header `X-CSRF-TOKEN`, cookie `securelab-af`, видача `GET /api/auth/csrf-token`, валідація `AntiforgeryFilter` на POST/PUT/DELETE incidents, triage і logout; login і register поза периметром (не довіряють наявній cookie).

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | POST /api/incidents | ЛР 2; сервер + клієнт | створює інцидент | так | так | explicit (AntiforgeryFilter) | REG-CSRF-01 |
| SC-02 | PUT /api/incidents/{id} | ЛР 4; DISCREPANCY: лише сервер | змінює назву й опис | так | так | explicit | REG-CSRF-02 |
| SC-03 | DELETE /api/incidents/{id} | ЛР 4; DISCREPANCY: лише сервер | видаляє інцидент | так | так | explicit | REG-CSRF-02 |
| SC-04 | POST /api/incidents/{id}/triage | ЛР 4; DISCREPANCY: лише сервер | змінює статус | так | так | explicit | REG-CSRF-02 |
| SC-05 | POST /api/auth/logout | ЛР 3; сервер + клієнт | завершує сеанс | так | так | explicit, до SignOutAsync | REG-CSRF-02 |
| SC-06 | POST /api/auth/login | ЛР 3; сервер + клієнт | створює сеанс | ні | так | не застосовується; login-CSRF — залишковий ризик | — |
| SC-07 | POST /api/auth/register | ЛР 3; сервер + клієнт | створює акаунт | ні | так | не застосовується; залишковий ризик | — |

- Rate limiting: login — 10/30 с за IP (повторно перевірено: 429 і відновлення); search — 5/10 с за id користувача або IP (дві partitions, 429, відновлення).
- Development vs Production: у Production немає OpenAPI (404), reset заборонено, cookie лише Secure, connection string поза Git.
- HTTPS/HSTS: у локальному стенді не налаштовано; висновок про транспорт у production не робиться.

## 9. Dependency and secret audit

`dotnet package list --vulnerable --include-transitive` (SDK 10.0.403, 22.11.2026, код 0): для обох проєктів джерело api.nuget.org не повідомило про advisories; таблиця рішень порожня; lock-файли увімкнено в `Directory.Build.props`. Секрети: широкий пошук `git grep` по 81 tracked-файлу — 229 збігів, точний пошук значень — 7 рядків; справжніх credentials немає, `local-study-password` — accepted, study-only (звіт, таблиці 1 і 6). Журнали: login, rate limit, authorization.denied і incident.status_changed без паролів, cookie й токенів (рис. 43).

## 10. Residual risks

- `GET /api/incidents/search` не вимагає входу й повертає інциденти всіх користувачів — не виправлено в межах ЛР 6; наступна дія: додати RequireAuthorization і фільтр за власником, адаптувати тести пошуку.
- Login-CSRF і CSRF на register: потребують окремого анонімного bootstrap токена.
- Транспорт у production (TLS, HSTS, reverse proxy) не перевірено.
- secure-app.html не отримує стилів під CSP (вбудований тег style).
- Журнали лише в console sink, без захищеного зберігання.

## 11. Conclusion

Обидві знахідки виправлено й закрито регресійними тестами, antiforgery поширено на весь cookie-периметр, наявні захисти перевірено на фактичних відповідях, і фінальний прогін пройдено на скинутій БД.

## 12. Evidence appendix

Звіт ЛР 6: рис. 5–8 (Production), 11–12 і 18 (F-01), 19–20 (CORS), 26–32 (CSRF), 34–36 (rate limiting), 38–39 (залежності й секрети), 40–43 (аудит і журнали). Зв'язок відповіді з журналом — через traceId (рис. 11–12). Значення паролів, cookie й токенів у доказах приховано.

## Декларація й журнал ШІ

Використовував асистента Claude (Anthropic) для пояснення вимог методички, підготовки чернеток коду, тестів, таблиць і цього огляду. Усі команди виконував сам на своєму стенді, результати на рисунках — фактичний вивід. Код перевіряв збіркою, тестами й ручною перевіркою в браузері; тексти адаптував до свого проєкту.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| 22.11.2026 | Claude | AntiforgeryFilter, csrf.js, адаптація тестів | підключив до своїх маршрутів і сторінок, звірив периметр | усі тести пройдено, ручна перевірка UI (табл. 5) |
| 22.11.2026 | Claude | виправлення F-01, політика search, audit-подія | перевірив на своєму коді й журналі | рис. 18, 36, 43 |
| 22.11.2026 | Claude | finding cards, таблиці, security review | звірив номери рисунків і хеші | відповідає фактичним результатам |

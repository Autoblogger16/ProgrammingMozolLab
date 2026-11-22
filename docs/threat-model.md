# Модель загроз SecureLab, ЛР 6

| Елемент | Що зафіксувати | Запис |
|---|---|---|
| Версія та середовище | review-start, профіль, seed/reset, SDK | review-start `f5f7c07` (тег v0.5.0), гілка `lab/6-hardening-review`; Development (`--launch-profile http`) і production-like (`--no-launch-profile`, `ASPNETCORE_ENVIRONMENT=Production`); reset `dotnet run --project src/SecureLab.Api -- --reset-database`; SDK 10.0.403 |
| Компоненти в межах огляду | | браузерний клієнт (`src/SecureLab.Api/Client`), ASP.NET Core API, PostgreSQL у Docker Compose (`infra/compose.yaml`), конфігурація (`appsettings*.json`, змінні середовища), console-журнали, NuGet-залежності. Redis не використовується |
| Активи | | облікові дані й cookie сеансу; власні інциденти користувачів; привілейований перехід статусу (triage); внутрішні коментарі; записи `incident_status_history` і події аудиту; секрети конфігурації (пароль seed, connection string) |
| Суб’єкти | | анонімний відвідувач; Reporter (alice, bob); Analyst (morgan); Administrator (admin); локальний розробник |
| Entry points | | HTTP-маршрути API; login, register, logout; форми сторінок auth-lab, browser-lab, secure-app; завантаження конфігурації; `dotnet restore`; журнали |
| Межі довіри | | browser→API, API→PostgreSQL, repository→build, environment→configuration |
| Наявні controls | | валідація (Lab02Endpoints), Identity + cookie (Lab03Identity), авторизація з власником і роллю (Lab04Endpoints/IncidentAccess), безпечний DOM через textContent (browser-lab.js), CORS лише для 4173 у Development, CSP/nosniff/no-referrer (Program.cs), antiforgery (AntiforgeryFilter, csrf.js), rate limiting login і search, безпечна 500 з traceId |
| Виключення | | production host, реальний TLS/HSTS, reverse proxy, зовнішній penetration test, Redis, вся історія Git |

## Схема меж довіри

```
[Browser client] --HTTP + cookie + X-CSRF-TOKEN--> [ASP.NET Core API] --Npgsql--> [PostgreSQL :54329 (127.0.0.1)]
                                                          ^
[repository + NuGet] --restore/build--> [build output] ---|
[environment / appsettings] --configuration--> [API startup]
```

## Очікувані властивості на межах

| Межа | Очікувана властивість | Конкретний test або перевірка |
|---|---|---|
| browser→API | зміни стану лише з валідною парою antiforgery-токенів; чужі дані недоступні; текст з API не стає кодом; лише точний CORS origin | `CsrfRegressionTests`, `AuthorizationTests A01–A12`, `XssRegressionTests`, REG-CORS-01 (рис. 19–20) |
| API→PostgreSQL | запити параметризовані, введення користувача не змінює SQL | `SqlInjectionRegressionTests.S02_...` |
| repository→build | залежності зафіксовані lock-файлом, без відомих advisories | `dotnet restore` з lock-файлом, `dotnet package list --vulnerable --include-transitive` (рис. 38) |
| environment→configuration | секрети поза Git; у Production немає OpenAPI і reset; помилки без внутрішніх деталей | `git grep` (табл. 1, 6), `ProductionProfileTests`, рис. 5–8, 11–12 |

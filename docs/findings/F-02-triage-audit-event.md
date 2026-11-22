# F-02. Дозволений перехід triage не мав події аудиту в журналі

**Статус:** Fixed  
**Актив:** журнал аудиту привілейованих змін статусу інциденту  
**Компонент:** маршрут `POST /api/incidents/{id}/triage` у `src/SecureLab.Api/Scaffolding/Lab04Endpoints.cs`  
**Пріоритет:** P3

## Передумови і межі огляду

Review-start commit `f5f7c07`; Development, `http://localhost:5080`; навчальні акаунти alice (Reporter)
і morgan (Analyst); reset командою `dotnet run --project src/SecureLab.Api -- --reset-database`.
Журнал API записано у файл (`> /tmp/api.log`). Поза межами: централізоване зберігання журналів.

## Відтворення

1. alice створює новий інцидент (статус New).
2. alice виконує `POST /api/incidents/{id}/triage` → 403; у журналі є
   `Security event authorization.denied ... action incident.triage ... result denied`.
3. morgan виконує той самий triage → 204, статус New → Triaged.
   Очікувано: подія в журналі про дозволений привілейований перехід.
   Фактично: у журналі нічого; зміну видно лише в таблиці `incident_status_history`.

## Вплив і ймовірність

**Статус перевірки:** оцінено за кодом і підтверджено журналом.

Журнал фіксував лише відмови, тож за ним не можна було відновити, хто й коли виконав
привілейовану дію. Дані не розкриваються, вплив низький, ймовірність потреби в аудиті —
середня → P3.

## Першопричина

У маршруті triage audit-подія писалася лише в гілці відмови (`IncidentAccess.Forbidden`),
а для успішного переходу виклику логера не було.

## Виправлення

Після `SaveChangesAsync` додано подію `incident.status_changed` в окрему категорію журналу
`SecureLab.Audit`: user, action, incident, result, старий і новий статус, час, trace.
Без тіла запиту, cookie і токенів. Коміт етапу 3, `Lab04Endpoints.cs`.

## Retest

Кроки 1–3: у журналі з'явився рядок
`Audit incident.status_changed: user ...003, action incident.triage, incident ..., result allowed, New -> Triaged, at ..., trace ...` (рис. 43).

## Positive regression

Відмова Reporter і далі 403 без запису в історії; Analyst і далі виконує triage (204), а повторний
triage дає 409 (тести `AuthorizationTests A06/A07`, `AuditTrailTests`).

## Залишковий ризик

Журнал пишеться в console sink; його захищене зберігання й ротація не налаштовані.

## Доказ

Тест `AuditTrailTests.Triage_DeniedReporter_NoChange_AllowedAnalyst_WritesAuditRecord`
(`dotnet test SecureLab.sln -c Release`, Passed) і фактичні рядки журналу на рис. 43.

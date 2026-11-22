# F-01. Відповідь 500 надсилалася без заголовків безпеки

**Статус:** Fixed  
**Актив:** захисні заголовки браузера (nosniff, Referrer-Policy, CSP) на всіх класах відповідей  
**Компонент:** спільна middleware заголовків безпеки в `src/SecureLab.Api/Program.cs`  
**Пріоритет:** P2

## Передумови і межі огляду

Review-start commit `f5f7c07` (тег v0.5.0); production-like profile (`ASPNETCORE_ENVIRONMENT=Production`,
`--no-launch-profile`, `-c Release`, `http://localhost:5080`); connection string навмисно на
недосяжний порт 54399 (`ConnectionStrings__SecureLab`), щоб отримати контрольовану 500.
Анонімний клієнт curl. Поза межами: інші причини 500, reverse proxy, HTTPS.

## Відтворення

1. Для порівняння в Development: `GET /api/incidents/9999...` (alice) → 404 Problem Details,
   у відповіді є `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
   `Content-Security-Policy` (рис. 13–14).
2. Запустити API в Production з недосяжною БД.
3. `POST /api/auth/login` з тілом `{"userName":"alice","password":"NotARealPassword1!"}`.
   Очікувано: 500 Problem Details з тими самими заголовками безпеки.
   Фактично: 500 `application/problem+json` з traceId, але **без** nosniff, Referrer-Policy і CSP (рис. 11).

## Вплив і ймовірність

**Статус перевірки:** спостережено локально (рис. 11–12).

Відповідь на помилку — єдиний клас відповідей, де браузерні захисти вимикаються: MIME sniffing,
витік referrer і відсутність frame-ancestors саме тоді, коли застосунок у нештатному стані.
Тіло 500 не містить даних користувача, тому вплив низький. Будь-яка 500 (збій БД, необроблений
виняток) відтворює стан без автентифікації, тому ймовірність середня → P2.

## Першопричина

Middleware встановлювала заголовки до `await next(context)`. Під час винятку
`ExceptionHandlerMiddleware` очищає відповідь (`Response.Clear()`), що видаляє вже встановлені
заголовки, і пише Problem Details без них.

## Виправлення

Заголовки встановлюються в `context.Response.OnStarting(...)`, тобто безпосередньо перед
надсиланням будь-якої відповіді, включно з 500. Значення заголовків і виняток для `/scalar` у
Development не змінено; для Referrer-Policy замість Append використано присвоєння.
Fixed commit `17b823e`, `src/SecureLab.Api/Program.cs`.

## Retest

Кроки 2–3 на `17b823e`: 500 `application/problem+json` тепер містить `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` і `Content-Security-Policy` з `frame-ancestors 'none'`; тіло
відповіді не змінилося (рис. 18).

## Positive regression

Крок 1 і решта класів відповідей (200 text/html, 200 json, 400, 404) зберігають ті самі заголовки;
очікувані помилки в Production лишаються 4xx (тест `Production_ExpectedErrors_Keep4xxSemantics`);
звичайний flow клієнта працює без CSP-порушень.

## Залишковий ризик

Перевірено лише контрольовану 500 через недосяжну БД; відповіді, сформовані поза конвеєром
застосунку (reverse proxy, Kestrel до middleware), не перевірялись.

## Доказ

Тест `ProductionProfileTests.UnexpectedError_KeepsSecurityHeaders`, команда
`dotnet test SecureLab.sln -c Release`, результат Passed. Ручний trace — рис. 11 (до) і рис. 18 (після).

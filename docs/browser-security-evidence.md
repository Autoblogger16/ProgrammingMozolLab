# Докази безпеки браузера (DEL-01)

Рівень: добрий («Добре»). Паролі, значення cookie/token та export browser storage не записуються.

## Стенд і Git-стан

- ОС: Windows, термінал MSYS2 UCRT64; браузер: Google Chrome 158.
- Origins: API і клієнт — http://localhost:5080; probe allowed — http://localhost:4173; probe disallowed — http://localhost:4174.
- Гілка: lab/5-browser-xss, створена від тегу v0.4.0.
- Vulnerable commit: ddd6e98 (lab5: install scaffold lab-05-start-v1 (vulnerable state)).
- Fixed commit: b7a90d9 (lab5: render description and comments as text via safe helper; seed comment marker).
- CORS commit: dd04842 (lab5: add Development-only CORS policy for probe 4173).
- CSP commit: 2f5af7e (lab5: add enforced CSP, move inline styles to CSS).
- Тег: v0.5.0 на фінальному перевіреному commit; fixed state перенесено в локальну main через git merge --ff-only.
- Механізм сеансу (Application → Cookies → http://localhost:5080): .AspNetCore.Identity.Application, Domain localhost, Path /, HttpOnly так, SameSite Lax, Secure ні. Value не записується.

## Гіпотеза й REG-XSS-01

Гіпотеза: текст з поля «Опис нового інциденту» без змін зберігається в Incident.Description, повертається API у полі description, а browser-lab.js записує його в div#description через innerHTML, тому браузер розбирає дані як HTML.

Передумови: локальний обліковий запис alice; скидання даних командою з reset-database; запуск API dotnet run --project src/SecureLab.Api --launch-profile http; marker з resources/lab05-marker.txt без змін; запис …0001 з коментарем …0005.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | description містить marker без змін | те саме значення символ у символ | звіт, рис. 27, 37 |
| DOM основного Description | у div#description створено елемент img | лише текстовий вузол | рис. 22, 36 |
| Дія marker | data-lab05-marker = 'executed' | null | рис. 19, 35, 73 |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | HTML-like рядок ставав елементом | усе відображено як текст | рис. 13–17, 38 |
| Довжина 4000 символів | зберігається, відображається | відображається повністю | рис. 16, 39 |
| Вікно Morgan; контроль Bob | Morgan: 'executed'; Bob: GET 404, null | Morgan: null | рис. 23–25 |

Finding: актив — сеанс користувача, який відкриває інцидент (Alice, Morgan). Першопричина — запис даних API через innerHTML у load() файлу browser-lab.js. Safe DOM diff — єдиний helper renderText(element, text) з textContent для назви, опису й коментарів. Retest — marker показано як текст, перевірка повертає null. Залишковий ризик — нові місця відображення даних мають використовувати той самий helper; CSP є додатковим захистом, а не виправленням.

REG-XSS-01: процедура, негативний контроль на ddd6e98 і очікуваний результат — звіт, таблиця 6.

## CORS і REG-CORS-01

Прогноз до зміни policy — звіт, таблиця 2.

Команди запуску probes:

    python3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
    python3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe

Policy Lab05BrowserProbe — навчальний Development-стенд: реєструється й застосовується лише в Development, один exact origin http://localhost:4173, метод GET, заголовок X-Lab-Cors-Probe, AllowCredentials(). Origin 4174 — негативний контроль. Штатна топологія — same-origin http://localhost:5080; у Production policy не реєструється.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | 200, CORS не потрібен | 200, CORS не потрібен | рис. 8, 69 |
| Allowed 4173 | 200, без ACAO, CORS error | 200, ACAO http://localhost:4173 | рис. 41, 48–49 |
| Disallowed 4174 | 200, без ACAO, CORS error | 200, без ACAO, CORS error | рис. 43, 54, 56 |
| Direct HTTP / curl | 200, відповідь читається | 200, відповідь читається | рис. 63 |

REG-CORS-01: browser evidence — рис. 76–77 (Origin http://localhost:4174, ACAO відсутній, відповідь не віддано сторінці); HTTP evidence — рис. 74–75 (для 4173 є Access-Control-Allow-Origin: http://localhost:4173, для 4174 Access-Control-* відсутні). Перевірка порядку UseCors до UseAuthentication: скрипт з 4173 прочитав 401 — рис. 47, 62. Curl читає відповідь, бо SOP — правило браузера; прямий клієнт проходить ті самі перевірки API.

## Додатково для «Добре»

Другий flow IncidentComment.Text: публічний seed-коментар 30000000-0000-0000-0000-000000000005 до інциденту Alice …0001 з тим самим marker (DbSeeder.cs). До виправлення — елемент img у div#comments і 'executed' (рис. 29–31), після — текстовий вузол і null (рис. 33–34). Обидва поля виводяться через єдиний helper renderText.

Preflight: з 4173 OPTIONS 204 з трьома Access-Control-Allow-* і actual GET 200 (рис. 52–53); з 4174 OPTIONS 204 без Access-Control-Allow-*, actual GET не надіслано (рис. 55, 57). Cookie-дослід: 4173 — 200 з ACAO і ACAC true (рис. 59); 4174 — запит виконано, відповідь не віддано (рис. 60); без AllowCredentials() — CORS error (рис. 61); без входу — 401 з CORS-заголовками (рис. 62). Кінцевий AllowCredentials() — лише в Development policy для 4173. Review XSS/CORS/CSRF/authorization — звіт (DEL-03), Етап 3, крок 8.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | усі ресурси з http://localhost:5080 | 'self' |
| script-src | app.js, browser-lab.js, скрипт auth-lab | 'self' через default-src |
| style-src | styles.css; inline-стилі index.html перенесено в нього | 'self' через default-src |
| connect-src | fetch лише до API на 5080 | 'self' через default-src |
| img-src | власних зображень немає | 'self' через default-src |
| frame-ancestors | вбудовування не потрібне | 'none', вказано явно |

Місце зміни: наявна middleware заголовків у Program.cs після UseStatusCodePages, Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; виняток лише для /scalar у Development. Enforcement: document 200 і один CSP header (рис. 68, 72); flow / і /browser-lab.html працює (рис. 69, 70); кероване порушення new Image().src = "http://localhost:4173/x.png" — «The action has been blocked» (рис. 70). Залишковий ризик: secure-app.html не входить у flow, її тег style під CSP не застосовується.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | nosniff (baseline) | забороняє MIME sniffing; не замінює правильний Content-Type і валідацію |
| Referrer-Policy | no-referrer (baseline, без змін) | адреса з Guid не передається іншим сайтам; не замінює заборону secrets в URL |
| frame-ancestors | 'none' | захист від clickjacking; не замінює авторизацію і виправлення XSS |

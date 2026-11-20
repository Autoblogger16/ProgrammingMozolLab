"""ЛР 4: перевірки після виправлення (локальний стенд, синтетичні дані).
Пароль береться зі змінної SeedUsers__Password; cookie і пароль не друкуються."""
import http.cookiejar, json, os, sys, urllib.error, urllib.request

sys.stdout.reconfigure(encoding='utf-8')
BASE = os.environ.get('SECURELAB_BASE', 'http://localhost:5080')
ALICE_INC = '20000000-0000-0000-0000-000000000001'   # Alice, Triaged
BOB_INC = '20000000-0000-0000-0000-000000000002'     # Bob, InProgress
ALICE_NEW = '20000000-0000-0000-0000-000000000003'   # Alice, New
UNKNOWN = '20000000-0000-0000-0000-0000000000ff'
COMMENT_ALICE = '30000000-0000-0000-0000-000000000001'     # публічний, інцидент Alice
COMMENT_BOB = '30000000-0000-0000-0000-000000000002'       # публічний, інцидент Bob
COMMENT_INTERNAL = '30000000-0000-0000-0000-000000000003'  # internal, інцидент Alice
PASSWORD = os.environ.get('SeedUsers__Password', '')
if not PASSWORD:
    sys.exit('Задайте SeedUsers__Password у цьому терміналі.')


class Session:
    def __init__(self, user):
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
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


def comment_ids(body):
    return [c['id'][-4:] for c in body.get('comments', [])] if isinstance(body, dict) else body


alice, morgan = Session('alice'), Session('morgan')
print('login alice / morgan: 204')

print('\n--- Політика 404: чужий = неіснуючий ---')
s1, b1 = alice.call('GET', f'/api/incidents/{BOB_INC}')
s2, b2 = alice.call('GET', f'/api/incidents/{UNKNOWN}')
strip = lambda b: {k: v for k, v in b.items() if k != 'traceId'}
print('Alice -> Bob      :', s1, b1.get('title'))
print('Alice -> unknown  :', s2, b2.get('title'))
print('однакові (без traceId):', strip(b1) == strip(b2), '| id у тілі:', BOB_INC in json.dumps(b1))

print('\n--- Internal comment у details ---')
s, b = alice.call('GET', f'/api/incidents/{ALICE_INC}')
print('Alice  -> details Alice, коментарі:', s, comment_ids(b))
s, b = morgan.call('GET', f'/api/incidents/{ALICE_INC}')
print('Morgan -> details Alice, коментарі:', s, comment_ids(b))

print('\n--- Дочірній ресурс /api/incident-comments/{id} ---')
print('Alice  -> публічний коментар свого інциденту:', alice.call('GET', f'/api/incident-comments/{COMMENT_ALICE}')[0])
print('Alice  -> коментар інциденту Bob           :', alice.call('GET', f'/api/incident-comments/{COMMENT_BOB}')[0])
print('Alice  -> internal коментар свого інциденту:', alice.call('GET', f'/api/incident-comments/{COMMENT_INTERNAL}')[0])
print('Morgan -> internal коментар                :', morgan.call('GET', f'/api/incident-comments/{COMMENT_INTERNAL}')[0])

print('\n--- Update ---')
s, _ = alice.call('PUT', f'/api/incidents/{ALICE_INC}',
    {'title': 'Підозрілий лист (оновлено власником)', 'description': 'Власник уточнив опис інциденту.',
     'ownerUserId': '10000000-0000-0000-0000-000000000002', 'status': 'Closed', 'severity': 'Critical'})
_, b = alice.call('GET', f'/api/incidents/{ALICE_INC}')
print('Alice  -> PUT свого (+ зайві ownerUserId/status/severity):', s)
print('         title:', b['title'], '| owner:', b['ownerDisplayName'], '| status:', b['status'], '| severity:', b['severity'])
print('Morgan -> PUT інциденту Alice:', morgan.call('PUT', f'/api/incidents/{ALICE_INC}',
    {'title': 'Аналітик змінює', 'description': 'Спроба аналітика змінити чужий опис.'})[0])

print('\n--- Delete ---')
print('Alice  -> DELETE інциденту Bob          :', alice.call('DELETE', f'/api/incidents/{BOB_INC}')[0])
print('Alice  -> DELETE свого (статус Triaged) :', alice.call('DELETE', f'/api/incidents/{ALICE_INC}')[0])
print('Morgan -> DELETE інциденту Alice        :', morgan.call('DELETE', f'/api/incidents/{ALICE_NEW}')[0])

print('\n--- Triage ---')
print('Alice  -> triage інциденту Bob:', alice.call('POST', f'/api/incidents/{BOB_INC}/triage', {})[0])
s, _ = morgan.call('POST', f'/api/incidents/{ALICE_NEW}/triage', {})
_, b = morgan.call('GET', f'/api/incidents/{ALICE_NEW}')
print('Morgan -> triage New-інциденту Alice:', s, '| статус після:', b['status'])
print('Morgan -> triage повторно (вже Triaged):', morgan.call('POST', f'/api/incidents/{ALICE_NEW}/triage', {})[0])

print('\nСценарій змінює стан; перед повторним запуском виконайте --reset-database.')

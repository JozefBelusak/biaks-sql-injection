# SQL Injection — dokumentácia

## Aplikácia

Webová aplikácia predstavuje študijný portál s nezabezpečenou a zabezpečenou verziou prihlasovania. Server používa štandardnú knižnicu Pythonu a SQLite, rozhranie tvorí HTML, CSS a JavaScript. Obe verzie pracujú s rovnakou databázou.

Študent má prístup k vlastnému profilu. Administrátor vidí tabuľku používateľov a môže upravovať ich meno, e-mail a študijnú skupinu. Zmeny sa ukladajú do databázy. Tlačidlo „Obnoviť pôvodné údaje“ obnoví počiatočné hodnoty týchto polí.

## Databáza

Tabuľka `users` obsahuje polia `id`, `username`, `password_hash`, `display_name`, `role`, `email` a `study_group`. Pri prvom spustení sa vytvorí databáza `data/lab.sqlite3` s ôsmimi fiktívnymi účtami. Staršia databáza sa automaticky rozšíri o nové polia a účty.

| Používateľ | Heslo | Rola |
| --- | --- | --- |
| `admin` | `Admin2026!` | administrátor |
| `student` | `Studium2026!` | študent |
| `o'connor` | `Apostrof2026!` | študent |
| `mnovak`, `pkovacova`, `lhorvath`, `eszabo`, `tbalaz` | `Studium2026!` | študent |

Heslá sa ukladajú ako PBKDF2-HMAC-SHA256 odtlačky s náhodnou soľou a 260 000 iteráciami. Funkcia `verify_password`, registrovaná v SQLite cez Python, overuje heslo v oboch verziách. Odtlačky porovnáva pomocou `hmac.compare_digest`.

## SQL Injection

Nezabezpečená vetva funkcie `authenticate` v `app.py` vkladá používateľské údaje priamo do SQL reťazca:

```sql
SELECT id, username, display_name, role
FROM users
WHERE username = 'admin' AND verify_password('hocico', password_hash) = 1
LIMIT 1;
```

Pri mene `admin' -- ` vznikne dotaz:

```sql
SELECT id, username, display_name, role
FROM users
WHERE username = 'admin' -- ' AND verify_password('hocico', password_hash) = 1
LIMIT 1;
```

Apostrof ukončí reťazec s menom a `--` zakomentuje zvyšok toho istého riadka vrátane overenia hesla. Dotaz vráti administrátorský účet aj pri nesprávnom hesle.

Server následne vytvorí administrátorskú reláciu. Útočník získa prístup k údajom používateľov a môže ich meniť cez administrátorské funkcie. Ide o narušenie dôvernosti aj integrity údajov. Následné úpravy používajú parametrizovaný `UPDATE`; ich zneužitie je dôsledkom obídenej autentifikácie.

Alternatívny vstup `' OR 1=1 -- ` vytvorí vždy pravdivú podmienku. Zraniteľné je aj pole hesla: pri mene `admin` vstup `x', password_hash) = 1 OR 1=1 -- ` obíde kontrolu rovnakým princípom.

## Zabezpečená verzia

Zabezpečená vetva používa pevný dotaz so zástupnými znakmi:

```sql
SELECT id, username, display_name, role
FROM users
WHERE username = ?
  AND verify_password(?, password_hash) = 1
LIMIT 1;
```

Údaje sa odovzdávajú samostatne:

```python
connection.execute(query, (username, password))
```

Text `admin' -- ` sa spracuje ako celá hodnota mena a nezmení štruktúru príkazu. Taký účet neexistuje, preto je prihlásenie odmietnuté. Parametrizácia zároveň správne spracuje legitímny apostrof v mene `o'connor`.

## Relácie a oprávnenia

Relácie sú uložené v pamäti servera a identifikované náhodným tokenom v `HttpOnly`, `SameSite=Strict` cookie. Platnosť je jedna hodina. Odhlásenie, nové prihlásenie a reštart servera reláciu zneplatnia. Pri prepnutí verzie aplikácia vykoná odhlásenie.

Server kontroluje reláciu a aktuálnu rolu pri každom administrátorskom čítaní alebo zápise. Neprihlásenému používateľovi vráti HTTP 401, študentovi HTTP 403. Zápisy a odhlásenie vyžadujú token proti CSRF v hlavičke `X-CSRF-Token`.

Prihlasovací dotaz používa spojenie iba na čítanie. Administrátorské zápisy používajú samostatné spojenie s parametrizovanými príkazmi. SQL dotazy, parametre a chyby sú v rozhraní dostupné po rozbalení položky „SQL dotaz“.

## Testy

```sh
python3 -m unittest discover -s tests -v
```

Vo Windows možno použiť `py -3` namiesto `python3`. Testy pokrývajú SQL Injection, prihlasovanie, oprávnenia, relácie, CSRF, ukladanie zmien a migráciu databázy. Používajú samostatnú dočasnú databázu.

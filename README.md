# DPI / TLS masquerade inspector for analyzing web-front behavior and TLS surface

Инструмент для практической оценки того, насколько сервер выглядит как «обычный веб‑фронт» с точки зрения активных сетевых проверок.

## What the tool does

`dpi_check.sh` выполняет эвристический анализ сетевой поверхности и помогает понять, насколько конфигурация похожа на нормальный web/TLS сервис:

- анализирует TLS, HTTP, ALPN и SNI-поведение;
- выявляет web-front паттерны и аномалии поверхности;
- формирует гипотезы по протоколу (а не «точное определение»).

## What it does NOT do

Важно:

- не гарантирует обнаружение VPN/proxy;
- не определяет точный протокол со 100% уверенностью;
- все выводы являются эвристикой.

## Installation

### Dependencies

Требуются:

- `bash`
- `curl`
- `openssl`
- `jq`
- `python3`

(Для некоторых окружений также могут использоваться системные утилиты вроде `nmap`/`nc`, если они доступны.)

### Clone and run

```bash
git clone <your-repo-url>
cd DPI_inspector
chmod +x dpi_check.sh validate.sh
bash dpi_check.sh example.com
```

## Usage examples

```bash
bash dpi_check.sh example.com
bash dpi_check.sh example.com 443 --sni domain.com
bash dpi_check.sh example.com --lang=ru
```

## Output explanation

Ключевые поля в итоговом блоке:

- **Reachability** — доступность цели и корректность сетевого отклика.
- **Camouflage** — насколько поведение похоже на обычный веб-сайт.
- **Exposure** — насколько заметны нетипичные/служебные признаки.
- **TLS surface class** — класс TLS-поверхности (обобщенный профиль).
- **Cert routing profile** — поведение сертификатов при разных SNI.
- **Surface risk** — интегральная оценка рискованности поверхности.
- **Protocol hypotheses** — вероятные семейства/режимы протокола.
- **Overall assessment** — общий практический вывод по маскировке.

## Interpretation guide

Примеры интерпретации:

- **"Ordinary web front"** → поведение близко к нормальному сайту.
- **"same_cert_broad_front"** → на «чужом» SNI часто отдается тот же сертификат.
- **"default_cert_broad_front"** → на «чужом» SNI отдается иной/дефолтный сертификат (обычно подозрительнее).

## Hardening hints

`dpi_check.sh` может показывать подсказки по укреплению поверхности:

- это рекомендации, а не гарантированные исправления;
- в первую очередь полезны для self-hosted конфигураций `nginx`/`caddy`.

См. также вспомогательный скрипт `harden_nginx.sh`.

## Example outputs (short)

### 1) normal site

```text
[01] Port scan              → 443/tcp open https
[02] TLS certificate        → CN=example.com, issuer=Let's Encrypt
[03] Mismatched SNI         → cert: CN=example.com
TLS surface class: ordinary_web_front
Surface risk: low
Overall assessment: Ordinary web front
```

### 2) same_cert_broad_front

```text
[01] Port scan              → 443/tcp open ssl/http
[02] TLS certificate        → CN=front.example.net, issuer=Public CA
[06] Mismatched SNI         → cert unchanged on unknown SNI
TLS surface class: same_cert_broad_front
Cert routing profile: broad (same cert)
Surface risk: medium
Overall assessment: Camouflage is broad but detectable
```

### 3) default_cert_broad_front

```text
[01] Port scan              → 443/tcp open ssl/http
[02] TLS certificate        → CN=service.example.org
[06] Mismatched SNI         → default/other cert on unknown SNI
TLS surface class: default_cert_broad_front
Cert routing profile: broad (default cert fallback)
Surface risk: elevated
Overall assessment: Front behavior looks less typical
```

Больше примеров в каталоге `examples/`.

## Related script

- `harden_nginx.sh` — helper для улучшения TLS surface на nginx.

## Release notes

- stable beta;
- inference is heuristic;
- improvements expected based on real-world feedback.

## Validation

```bash
bash validate.sh
```

## License

MIT

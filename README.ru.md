# DPI Masquerade Inspector

Инструмент активного анализа TLS/TCP/UDP-поверхности. Зондирует целевой хост, классифицирует сетевое поведение по семейству протоколов и оценивает, насколько убедительно сервер выглядит как обычный HTTPS-веб-фронт.

> **English version:** [README.md](README.md)

---

## Что делает инструмент

`dpi_check.sh` выполняет эвристический анализ сетевой поверхности и формирует структурированный вердикт:

- инспекция TLS-сертификата (CN, издатель, покрытие SAN, алгоритм ключа, срок действия)
- проверка согласования ALPN (реально согласованный ALPN из TLS vs профиль HTTP-ответа)
- поведение SNI: совпадающий, иностранный (`test.invalid`) и без-SNI зонды
- HTTP-поверхность: случайный путь, редирект, размер тела, профиль заголовков
- экспозиция транспортов: WebSocket (21 путь) и gRPC (14 путей + 9 путей строгого режима)
- проверка принятия CONNECT-прокси
- опциональный фингерпринт H2 SETTINGS через `nghttp` (MAX\_CONCURRENT\_STREAMS)
- режим QUIC/UDP через `quic_probe.py` (`aioquic`)
- разбор ссылок обмена VPN (`vless://`, `hysteria2://`, `trojan://`, `ss://`)
- инференс семейства протоколов с оценкой уверенности по **10 семействам**
- советы по усилению для самостоятельных конфигураций nginx/Caddy
- машиночитаемый JSON-вывод (`--json`)
- слой интерпретации на русском или английском (`--lang=ru`)

## Что инструмент НЕ делает

- не гарантирует обнаружение VPN или прокси
- не определяет точный протокол со 100% уверенностью
- все вердикты — это эвристические оценки

---

## Установка

### Обязательные зависимости

| Инструмент | Назначение |
|-----------|-----------|
| `bash` | Среда выполнения |
| `curl` | HTTP-зондирование |
| `openssl` | TLS-рукопожатие и извлечение сертификатов |
| `jq` | Сборка JSON |
| `python3` ≥ 3.9 | Инференс протоколов (`protocol_infer.py`) |
| `nmap` | Сканирование портов и фингерпринт сервиса |
| `nc` (netcat) | Резервная TCP-проверка |
| `dig` / `getent` | DNS-разрешение |

### Опциональные зависимости

| Инструмент | Назначение |
|-----------|-----------|
| `nghttp` (`nghttp2-client`) | Инспекция фрейма H2 SETTINGS (MAX\_CONCURRENT\_STREAMS) |
| Python-пакет `aioquic` | QUIC/UDP-зондирование (`quic_probe.py`) |
| Python-пакет `cryptography` | Извлечение сертификатов в режиме QUIC |

Установка опциональных Python-пакетов:

```bash
pip install aioquic cryptography
```

Установка `nghttp2-client` на Debian/Ubuntu:

```bash
apt install nghttp2-client
```

### Клонирование и запуск

```bash
git clone <url-репозитория>
cd dpi-check
chmod +x dpi_check.sh validate.sh
bash dpi_check.sh example.com
```

---

## Использование

```
dpi_check.sh <цель> [порт] [опции]
```

### Опции

| Флаг | Описание |
|------|----------|
| `-m, --mode tcp\|udp\|auto` | Режим протокола (по умолчанию: автоопределение через TCP-зонд) |
| `-s, --sni ДОМЕН` | Переопределить SNI для всех TLS-зондов |
| `-t, --timeout N` | Таймаут зонда в секундах (по умолчанию: 5) |
| `--json` | Машиночитаемый JSON-вывод (включает обогащённый инференс) |
| `--debug-infer` | Показать внутренности инференса и таблицу ранжированных оценок |
| `--hardening-hints` | Показать советы по усилению в текстовом выводе (включено по умолчанию) |
| `--recommend-fixes` | Псевдоним для `--hardening-hints` |
| `--lang=ru\|en` | Язык слоя интерпретации (по умолчанию: en) |
| `--no-asn` | Пропустить внешний поиск ASN (ipinfo.io) |
| `--no-color` | Простой вывод без ANSI-цветов |
| `-h, --help` | Показать справку |

### Примеры

```bash
# Базовая TCP/TLS-инспекция
bash dpi_check.sh example.com

# Указать порт и переопределить SNI
bash dpi_check.sh example.com 443 --sni front.example.net

# Принудительный режим UDP/QUIC
bash dpi_check.sh example.com 443 --mode udp

# Разобрать ссылку обмена VPN напрямую
bash dpi_check.sh "vless://uuid@host:443?sni=front.com"
bash dpi_check.sh "hysteria2://pw@host:443?sni=front.com"

# JSON-вывод для машинной обработки
bash dpi_check.sh example.com --json | jq .inference

# Русский вывод
bash dpi_check.sh example.com --lang=ru

# Отладка оценок инференса
bash dpi_check.sh example.com --debug-infer

# Пропустить поиск ASN (конфиденциальность)
bash dpi_check.sh example.com --no-asn
```

---

## Поля вывода

### Итоговые оценки

| Поле | Описание |
|------|----------|
| **Reachability** | TCP/UDP-порт открыт и TLS-рукопожатие успешно |
| **Camouflage** | Насколько поверхность похожа на обычный HTTPS-сайт |
| **Exposure** | Насколько заметны необычные или сервисные сигналы |
| **Confidence** | Общая уверенность в вердикте (снижается для IP-целей без `--sni`, неудачного извлечения сертификата и т.д.) |

### Блок инференса

| Поле | Описание |
|------|----------|
| **TLS surface class** | Классифицированный профиль маршрутизации SNI/сертификата (см. ниже) |
| **Cert routing profile** | Поведение при зондировании с иностранным SNI и без SNI |
| **Surface risk** | Интегральный уровень риска: `low` / `medium` / `elevated` / `high` |
| **Protocol hypotheses** | Ранжированный список вероятных семейств протоколов с оценками уверенности |
| **Overall assessment** | Практический человекочитаемый вердикт |
| **Hardening hints** | Применимые советы для nginx/Caddy (если применимо) |

### Классы TLS-поверхности

| Класс | Значение |
|-------|----------|
| `strict_sni_front` | Сервер отклоняет или закрывает при иностранном/без-SNI — наиболее узкая поверхность |
| `same_cert_broad_front` | Иностранный/без-SNI принимается с **тем же** сертификатом — более широкая поверхность |
| `default_cert_broad_front` | Иностранный/без-SNI возвращает **другой** (дефолтный) сертификат — наиболее сильная аномалия |

### Отдельные проверки (findings)

| ID | Категория | Что проверяет |
|----|-----------|---------------|
| `port_scan` | reachability | TCP открыт через nmap или резервный метод |
| `tls_cert` | camouflage | Публичный CA, CN, срок действия, алгоритм ключа |
| `tls_version` | camouflage | TLSv1.3 / TLSv1.2 / устаревшая версия |
| `http_response` | camouflage | HTTP 200, редирект, размер тела (<512 Б — notice) |
| `http_headers` | camouflage | Профиль `Server`, `HSTS`, `Content-Type` |
| `alpn_profile` | camouflage | Согласованный ALPN (`h2`, `http/1.1`, нет) |
| `cert_san` | camouflage | Покрытие SAN проверяемым SNI (с поддержкой подстановок) |
| `mismatched_sni` | exposure | Сертификат/поведение на иностранном SNI `test.invalid` |
| `no_sni` | exposure | Сертификат/поведение при отсутствии SNI |
| `random_path` | exposure | Ответ на случайный 32-символьный hex-путь |
| `connect_probe` | exposure | Принимается ли HTTP CONNECT |
| `ws_transport` | exposure | WebSocket upgrade по 21 типичному пути |
| `grpc_transport` | exposure | gRPC по 14 путям; строгий HTTP/2 по 9 путям |
| `h2_settings` | exposure | MAX\_CONCURRENT\_STREAMS через nghttp (опционально) |

---

## Семейства протоколов

Движок инференса сравнивает цель с **10 семействами протоколов**:

| Семейство | Описание |
|-----------|----------|
| `ordinary_web_front` | Ведёт себя как обычный публичный HTTPS-сайт |
| `broad_tls_front` | Принимает многие SNI / без-SNI, но в остальном похож на веб |
| `cdn_or_reverse_proxy_front` | Заголовки edge/CDN (`via`, `cf-ray`, `x-cache` и т.д.) |
| `tls_camouflage_relay` | TLS-фронт с туннелем за ним; минимальные сигналы экспозиции |
| `default_cert_tls_front` | Дефолтный сертификат на иностранном SNI — типичная ошибка конфигурации Nginx/Caddy или намеренный catch-all |
| `exposed_v2ray_transport` | WS или gRPC-транспорт явно доступен на известных путях |
| `http_tunneling_front` | HTTP CONNECT принимается — явный туннелирующий прокси |
| `quic_relay` | QUIC-рукопожатие успешно; вероятно QUIC-ретранслятор (Hysteria2 и т.д.) |
| `direct_http_proxy` | CONNECT принимается на порту открытого HTTP |
| `no_clear_tunnel_evidence` | Нет сильных индикаторов ни для одного туннельного семейства; скорее всего обычный сайт |

---

## Руководство по интерпретации

| Вердикт | Практическое значение |
|---------|-----------------------|
| `Ordinary web front` | Поверхность неотличима от обычного сайта |
| `Camouflage is broad but detectable` | Сервер принимает иностранный SNI с тем же сертификатом — сканируемо, но слабо |
| `Front behavior looks less typical` | Дефолтный сертификат на иностранном SNI — обнаруживаемый паттерн |
| `Transport signals detectable` | WS или gRPC-эндпоинты видны на типичных путях |
| `CONNECT proxy detected` | Сервер принимает HTTP CONNECT туннелирование |

---

## Формат JSON-вывода

```bash
bash dpi_check.sh example.com --json
```

Поля верхнего уровня:

```json
{
  "host": "example.com",
  "port": 443,
  "mode": "tcp",
  "ip": "93.184.216.34",
  "asn": "AS15133 ...",
  "sni": "example.com",
  "scores": {
    "reachability": {"pts": 4, "max": 4, "pct": 100},
    "camouflage":   {"pts": 8, "max": 10, "pct": 80},
    "exposure":     {"pts": 2, "max": 6, "pct": 33}
  },
  "findings": [...],
  "inference": {
    "tls_surface_class": "strict_sni_front",
    "cert_routing_profile": "strict",
    "surface_risk": "low",
    "hypotheses": [
      {"family": "ordinary_web_front", "confidence": 0.87, "rank": 1}
    ],
    "overall_assessment": "Ordinary web front",
    "hardening_hints": []
  }
}
```

---

## Оценка уверенности

Процент уверенности отражает надёжность вердикта:

- **Высокая (≥ 85 %)** — полный TCP-режим с SNI и извлечённым сертификатом
- **Средняя (60–84 %)** — IP-цель без `--sni` или неполные данные
- **Низкая (< 60 %)** — QUIC-режим без сертификата или IP-только цель

---

## Связанные файлы

| Файл | Назначение |
|------|-----------|
| `dpi_check.sh` | Основной скрипт инспектора |
| `protocol_infer.py` | Движок оценки и рендерер текста |
| `quic_probe.py` | QUIC/UDP зонд рукопожатия |
| `lang.sh` | Вспомогательный модуль локализации |
| `harden_nginx.sh` | Вспомогательный скрипт усиления TLS-поверхности nginx |
| `validate.sh` | Набор самотестов |

---

## Валидация

```bash
bash validate.sh
```

Запускает встроенный набор самотестов. Для Python-юнит-тестов:

```bash
python3 -m pytest tests/ -v
# или напрямую:
python3 -c "from tests.test_protocol_infer import *; test_ordinary_web(); test_exposed_transport(); test_default_cert()"
```

---

## Лицензия

MIT

# Agent-TZ.md — Техническое Задание для ИИ-Агента

## Проект: KepchukAPI (Kepchuk Central Server) — Rust + C Edition

> **Агенту:** Прочитай этот документ полностью. Затем составь `PLAN.md` с шагами по фазам.
> После утверждения плана — приступай к реализации. Не перескакивай через фазы.
> Если что-то непонятно — пиши `// TODO: уточнить у владельца`, принимай консервативное решение
> и продолжай. Владелец ушел пить чай. Не подведи его.

---

## 0. Контекст и Философия Проекта

### 0.1 Что мы строим
KepchukAPI — это **Центральный Сервер (ЦС)** для сети ИИ-персонажей (девушек/парней). Боты (клиенты) общаются с пользователями в мессенджерах, тратят токены пользователя, а ЦС следит за балансами, тарифами и безопасностью.

### 0.2 Манифест (ОБЯЗАТЕЛЕН К СОБЛЮДЕНИЮ)
1. **Никаких внешних крипто-библиотек.** SHA-256 и HMAC — только чистый C (C11).
2. **Никаких «черных ящиков».** Если стандартная обертка не нравится — пишем свою.
3. **Опенсорс (BSD-3-Clause).** Код открыт. Безопасность — на секретах, а не на обфускации.
4. **Портируемость.** Работает на x86_64, ARM (Raspberry Pi), Windows, macOS.
5. **Без ассемблера.** Мы не ФБР. Компилятор с `-O2/-O3` достаточно умён.
6. **Минимализм.** Никаких `boost`, `libssl`. Если нужен SHA — пишем на C.
7. **Rust для API.** Сеть, типы, безопасность — на Rust. Математика — на C.
8. **CGO/FFI без магии.** C-код компилируется в статическую библиотеку, линкуется с Rust.

### 0.3 Стек
- **Сетевой слой / API:** Rust 1.75+ (`axum` + `tokio` + `tower`).
- **Крипто-слой:** Чистый C (C11), компилируется в `libkep_crypto.a`.
- **Мост:** `cc` crate для сборки C, `bindgen` для генерации Rust-обёрток.
- **Хранение:** SQLite (для MVP) → PostgreSQL (для продакшена). Абстракция через `trait`.
- **Кэш Nonce:** `DashMap` (in-memory) для MVP → Redis (для продакшена).
- **Сборка:** `Cargo.toml` + `build.rs`. Один статический бинарник.

### 0.4 Архитектура
```text
┌─────────────────────────────────────────────────────┐
│ KepchukAPI (Rust / axum)                            │
│  ┌──────────────┐   ┌──────────────┐  ┌───────────┐ │
│  │ HTTP/gRPC    │   │ WebSocket    │  │ Webhooks  │ │
│  │ Сервер       │   │ Хаб          │  │ Обработчик│ │
│  └──────┬───────┘   └──────┬───────┘  └─────┬─────┘ │
│         │                  │                │       │
│         └──────────────────┼────────────────┘       │
│                            ▼                        │
│                 ┌────────────────────────┐          │
│                 │ Ядро Kepchuk (Rust)    │          │
│                 │ - Биллинг              │          │
│                 │ - TTL/Nonce            │          │
│                 │ - Проверка подписей    │          │
│                 └───────────┬────────────┘          │
│                             │ FFI                   │
│                 ┌───────────▼────────────┐          │
│                 │ Крипто-модуль (C)      │          │
│                 │ - SHA-256 (чистый C)   │          │
│                 │ - HMAC (чистый C)      │          │
│                 │ - HEX (чистый C)       │          │
│                 │ - Constant-time cmp    │          │
│                 └────────────────────────┘          │
└─────────────────────────────────────────────────────┘
```

### 0.5 Структура репозитория
```text
kepchuk-api/
├── Agent-TZ.md             # Этот файл
├── PLAN.md                 # План работы (создает агент)
├── README.md               # Для людей (философия, quickstart)
├── SECURITY.md             # Модель угроз
├── LICENSE                 # BSD-3-Clause
├── Cargo.toml              # Rust-манифест
├── build.rs                # Сборка C + bindgen
├── src/
│   ├── main.rs             # Точка входа (axum-сервер)
│   ├── config.rs           # Конфиг через env
│   ├── api/
│   │   ├── mod.rs
│   │   ├── router.rs       # axum-роутинг
│   │   ├── middleware.rs   # Auth middleware (API-Key + HMAC + TTL + Nonce)
│   │   ├── subs.rs         # /kep/subs/*
│   │   ├── block.rs        # /kep/block/*
│   │   └── bot.rs          # /kep/bot/*
│   ├── crypto/             # FFI-обертка над C
│   │   ├── mod.rs
│   │   ├── ffi.rs          # bindgen-сгенерированные типы
│   │   └── wrapper.rs      # Безопасные Rust-функции
│   ├── domain/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── bot.rs
│   │   ├── billing.rs
│   │   └── errors.rs
│   ├── storage/
│   │   ├── mod.rs          # trait Storage
│   │   ├── sqlite.rs
│   │   └── memory.rs       # Для тестов
│   └── nonce/
│       ├── mod.rs          # trait NonceStore
│       └── memory.rs       # DashMap
├── csrc/                   # Чистый C-код
│   ├── sha256.c
│   ├── sha256.h
│   ├── hmac.c
│   ├── hmac.h
│   ├── secure_compare.c
│   ├── secure_compare.h
│   └── kep_crypto.h        # Единый заголовок для bindgen
├── tests/
│   ├── integration_test.rs # e2e-тесты
│   └── crypto_vectors.rs   # RFC 4231
├── migrations/             # SQL-миграции
│   └── 001_init.sql
└── docs/
    ├── API.md
    └── BOT_GUIDE.md
```

---

## 1. Модель Безопасности (КРИТИЧНО)

### 1.1 Аутентификация: Три Уровня
Каждый запрос от бота должен пройти **все три** проверки:

**Уровень 1: API-Key (идентификация)**
- Заголовки: `X-Bot-ID` + `X-API-Key`.
- API-Key — случайная строка 32+ байта, хранится в БД в хешированном виде (SHA-256).
- Если ключ невалиден → `401 Unauthorized`.

**Уровень 2: HMAC-подпись с TTL (доказательство знания секрета)**
- Заголовки: `X-Timestamp` (unix seconds), `X-Signature` (hex).
- Формула (ОТКРЫТА, в опенсорсе):
```text
time_window = timestamp / 300 // окно 5 минут
message = bot_id + ":" + timestamp + ":" + nonce + ":" + body_sha256_hex
signature = HMAC_SHA256(bot_secret, time_window_str + ":" + message)
```
> **Внимание агенту:** точную формулу согласовать с владельцем.
> Базовая версия: `HMAC(secret, floor(ts/300))`.
- Проверка TTL: `|now - timestamp| <= 300` секунд. Иначе `401 Signature expired`.

**Уровень 3: Nonce (защита от Replay)**
- Заголовок: `X-Nonce` (UUID v4 или 16 случайных байт hex).
- Сервер хранит использованные `(bot_id, nonce)` в кэше на 5 минут.
- Если nonce уже видели → `409 Conflict (Replay detected)`.

### 1.2 Constant-Time Comparison
- **НИКОГДА** не сравнивай подписи через `==`.
- На C: `kep_secure_compare(a, b, len)` — побайтовое XOR + OR, без ветвлений.
- На Rust: использовать `subtle::ConstantTimeEq`.
- Тест на это обязателен.

### 1.3 Test Vectors (RFC 4231)
- Обязательно покрыть тестами SHA-256 и HMAC-SHA256 из RFC 4231.
- Файл: `tests/crypto_vectors.rs`.
- Если тесты не проходят — сборка падает.

---

## 2. API Эндпойнты (Первая Версия)

### 2.1 Группа `/kep/auth`
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/kep/auth/register` | Регистрация бота. Возвращает `bot_id` + `api_key` + `bot_secret`. **Один раз.** |
| POST | `/kep/auth/rotate` | Ротация секрета (требует старый API-Key). |

### 2.2 Группа `/kep/subs`
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/kep/subs/status/{user_id}` | Баланс + активный тариф юзера. |
| POST | `/kep/subs/consume` | Списать токены. Body: `{user_id, tokens, reason}`. |
| POST | `/kep/subs/purchase` | Вебхук от платежки. Body: `{user_id, package, tokens}`. |

### 2.3 Группа `/kep/block`
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/kep/block/check/{user_id}` | Заблокирован ли юзер. |
| POST | `/kep/block/user` | Заблокировать. Body: `{user_id, reason, duration_hours}`. |

### 2.4 Группа `/kep/bot`
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/kep/bot/heartbeat` | Бот сообщает, что жив. Body: `{status, load}`. |
| GET | `/kep/bot/config/{bot_id}` | Конфиг бота (лимиты, фичи). |

### 2.5 Служебные
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/healthz` | Liveness probe. |
| GET | `/readyz` | Readiness probe (проверка БД). |
| GET | `/metrics` | Prometheus-метрики (опционально). |

---

## 3. План Работы по Фазам

### Фаза 1: Крипто-фундамент (C + FFI)
**Цель:** Работающий SHA-256 и HMAC-SHA256 на чистом C, доступный из Rust.
- [ ] `csrc/sha256.c` — реализация SHA-256 (C11, без библиотек).
- [ ] `csrc/sha256.h` — заголовок.
- [ ] `csrc/hmac.c` — HMAC-SHA256 поверх SHA-256.
- [ ] `csrc/hmac.h` — заголовок.
- [ ] `csrc/secure_compare.c` + `.h` — constant-time сравнение.
- [ ] `csrc/kep_crypto.h` — единый заголовок для bindgen.
- [ ] `build.rs` — сборка C через `cc` crate + генерация биндингов через `bindgen`.
- [ ] `src/crypto/wrapper.rs` — безопасные Rust-функции поверх FFI.
- [ ] `tests/crypto_vectors.rs` — тесты RFC 4231.
- [ ] **Критерий готовности:** `cargo test --test crypto_vectors` — зелёный.

### Фаза 2: Скелет HTTP-сервера
**Цель:** Сервер поднимается на axum, отвечает на `/healthz`.
- [ ] `Cargo.toml` — зависимости: axum, tokio, tower, tower-http, serde, serde_json, tracing, tracing-subscriber.
- [ ] `src/main.rs` — инициализация tokio runtime + axum::serve.
- [ ] `src/config.rs` — конфиг через env (`KEPCHUK_PORT`, `KEPCHUK_DB_URL`).
- [ ] `src/api/router.rs` — сборка роутера.
- [ ] `/healthz` и `/readyz`.
- [ ] Graceful shutdown (SIGTERM через tokio::signal).
- [ ] Логирование через tracing.
- [ ] **Критерий:** `cargo run` + `curl localhost:8080/healthz` → 200 OK.

### Фаза 3: Аутентификация (Middleware)
**Цель:** Любой защищенный эндпойнт требует API-Key + HMAC + TTL + Nonce.
- [ ] `src/api/middleware.rs` — tower::Layer для аутентификации.
- [ ] `src/nonce/memory.rs` — кэш nonce на DashMap с TTL-очисткой.
- [ ] Проверка TTL (окно 5 минут).
- [ ] Проверка подписи через crypto-wrapper.
- [ ] Тест: запрос без подписи → 401.
- [ ] Тест: просроченный timestamp → 401.
- [ ] Тест: повторный nonce → 409.
- [ ] **Критерий:** `cargo test` — зелёный.

### Фаза 4: Домен и Хранилище
**Цель:** Биллинг работает в памяти, потом в SQLite.
- [ ] `src/storage/mod.rs` — trait Storage с методами get_user, update_balance, consume_tokens, get_bot, и т.д.
- [ ] `src/storage/memory.rs` — реализация на HashMap для тестов.
- [ ] `src/storage/sqlite.rs` — реализация на rusqlite (с миграциями).
- [ ] `migrations/001_init.sql` — схема таблиц.
- [ ] `src/domain/billing.rs` — логика списания (атомарность, проверка баланса).
- [ ] `src/domain/user.rs`, `bot.rs`.
- [ ] **Критерий:** тесты на биллинг (списание, недостаток баланса, идемпотентность).

### Фаза 5: Эндпойнты `/kep/subs` и `/kep/block`
**Цель:** Реализовать все эндпойнты из раздела 2.
- [ ] `src/api/subs.rs`.
- [ ] `src/api/block.rs`.
- [ ] `src/api/bot.rs`.
- [ ] Валидация входных данных через serde + validator.
- [ ] Ошибки в едином формате: `{"error": {"code": "...", "message": "..."}}`.
- [ ] **Критерий:** e2e-тест: регистрация бота → списание → проверка баланса.

### Фаза 6: Документация и Go-клиент (опционально)
**Цель:** Любой может написать бота за 15 минут.
- [ ] `docs/API.md` — описание всех эндпойнтов с примерами.
- [ ] `docs/BOT_GUIDE.md` — туториал «пишем первого бота».
- [ ] `SECURITY.md` — модель угроз, как проверить сборку.
- [ ] `README.md` — quickstart (5 строк).
- [ ] **Критерий:** новый разработчик по README поднимает сервер за 5 минут.

### Фаза 7: Сборка и Релиз
**Цель:** Один статический бинарник под платформы.
- [ ] GitHub Actions: CI (тесты + сборка).
- [ ] **Критерий:** `cargo build --release` собирается и работает.

---

## 4. Правила для Агента

### 4.1 Что делать
✅ Сначала план. Составь PLAN.md с шагами по фазам, потом реализуй.
✅ Тесты для всего. Если код нельзя протестировать — перепиши код.
✅ Комментарии в C и Rust — очень мало, в нижнем регистре.
✅ Весь код и документация — на английском.
✅ Rust-идиомы: ? вместо unwrap, Result вместо паники, tracing вместо println.
✅ Ошибки — значения. Не паникуй без причины.
✅ State везде.
✅ cargo fmt и cargo clippy перед коммитом.

### 4.2 Что НЕ делать
❌ Не тянуть крейты без разрешения. Разрешено: axum, tokio, tower, tower-http, serde, serde_json, tracing, tracing-subscriber, cc, bindgen, hex, dashmap, rusqlite, subtle, uuid, chrono.
❌ Не писать на ассемблере.
❌ Не использовать openssl, ring, libsodium. Крипто — только чистый C.
❌ Не сравнивать подписи через `==`.
❌ Не хардкодить секреты. Только env.
❌ Не перескакивать через фазы.

### 4.3 Если что-то непонятно
Пиши `// TODO: clarify with owner - <question>`.
Принимай самое консервативное решение.
Никогда не удаляй существующий код без причины.

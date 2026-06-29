---
name: scan-composer
description: Marketplace pre-submission security-flow для ОДНОГО Bitrix-модуля — сырой аудит и BUS-aware пересмотр severity. Точка входа сканера (engine claude-cli). Вызывается с одним аргументом — путём к распакованному модулю. Headless (без UI).
---

# Bitrix Module Security — orchestrated entry

Это **точка входа** скана для движка `claude-cli`. Ты запускаешь security-flow
проверки одного Bitrix-модуля, headless (контейнер изолирован, внешней сети нет —
только relay модели; никакого веб-UI).

Сам этот скилл эвристик аудита не содержит. Аудит — в скилле `scan`, политика
severity — в `journal-review`. Те же шаги в человекочитаемом виде описаны в
`using-marketplace-sec` (upstream-референс).

Тебе дают в промпте:
- **MODULE_DIR** — путь к распакованному PHP-исходнику модуля (аргумент вызова).
- **RESULT_PATH** — путь, куда сохранить итоговый JSON-отчёт.
- **REVIEW_SCRIPT** — абсолютный путь к `review_journal.py` (детерминированный
  скрипт пересмотра severity). Уже на диске — **используй путь как есть, НЕ ищи
  его через `find`**.

Если путь к `REVIEW_SCRIPT` в промпте не дан — сообщи об этом и останови flow.

## Обязательная последовательность

Выполни ВСЕ шаги по порядку. Нельзя писать сырой аудит сразу в RESULT_PATH —
в RESULT_PATH должен лежать **пересмотренный** (reviewed) отчёт после шага 2.

1. **SCAN.** Вызови скилл `scan` с аргументом MODULE_DIR — проведи тщательный
   security-аудит по его методологии (включая `scan/references/*`). Сохрани сырой
   JSON в `/tmp/raw-scan.json`. Формат строго: `{success, requestId,
   data:{vulnerabilities[], summary, scannedFiles, riskLevel, auditedFiles}}`;
   у КАЖДОЙ находки есть `file, line, type, severity, description,
   recommendation, fix`.

2. **REVIEW (BUS-aware severity).** Выполни (подставь реальные RESULT_PATH и
   REVIEW_SCRIPT из промпта):

   python3 "$REVIEW_SCRIPT" /tmp/raw-scan.json --output "RESULT_PATH"

   Скрипт сохраняет исходные поля, заменяет только severity на reviewed-severity,
   добавляет узел reviewed к каждой находке и data.reviewSummary. Теперь
   RESULT_PATH — финальный отчёт.

   **При НЕнулевом коде выхода `review_journal.py`** скрипт НИЧЕГО не выдумывает —
   он печатает в `stderr` полный список реальных пробелов. Действуй
   детерминированным циклом (**максимум 3 итерации**):

   1. Прочитай `stderr`. Машиночитаемый список — в строке
      `REVIEW_VALIDATION_ERRORS: [...]` (JSON-массив **всех** проблемных находок
      сразу). Каждый элемент: `index`, `file`, `line`, `type`, `missingKeys`,
      `invalidSeverity`.
   2. Для **каждой** перечисленной находки сделай точечную проверку: открой
      (`Read`) её `file` (при необходимости по `line`) и впиши в
      `/tmp/raw-scan.json` **реальное** недостающее значение, выведенное из кода —
      настоящие `description`/`recommendation`/`fix`, либо корректную `severity` из
      набора `{critical, high, medium, low}`. Чини **все** находки из списка за один
      проход. **Никаких заглушек/плейсхолдеров.**
   3. Перезапусти ту же команду `review_journal.py`. Повторяй цикл, пока код выхода
      не станет 0.

   Если за 3 итерации сойтись не удалось — НЕ подсовывай выдуманные данные: останови
   flow с ошибкой (внешний слой перезапустит скан заново). Честный повтор лучше
   фиктивного отчёта.

3. **VALIDATE финал.** Сначала синтаксис: `python3 -m json.tool "RESULT_PATH"`.
   Затем — самопроверка **реальной финальной формы** перед тем как объявить готово.
   Прочитай `RESULT_PATH` и убедись по каждому пункту:
   - `data.summary` — это **строка** (не объект, не массив).
   - `data.scannedFiles` — это **число**.
   - `data.riskLevel` ∈ `{critical, high, medium, low, none}`.
   - `data.auditedFiles` — это **массив строк**.
   - у **каждого** `data.vulnerabilities[i]` присутствуют все 7 ключей
     (`file, line, type, severity, description, recommendation, fix`), причём
     `description`, `recommendation`, `fix` — **непустые**.
   - `data.riskLevel` **равен** максимальной severity среди находок (`none`, если
     находок нет).

   **Если самопроверка нашла пробел** — НЕ вставляй плейсхолдер. Исправь
   **реальное** содержимое: перечитай файл модуля и впиши настоящий
   `fix`/`recommendation`/`description`, затем **заново выполни шаг REVIEW** (п. 2,
   тем же ограниченным циклом — максимум 3 итерации), чтобы reviewed-отчёт был
   пересобран из исправленных данных. Если сойтись не удалось — останови flow с
   ошибкой, не сдавай фиктивный отчёт.

4. **Резюме одной строкой:** reviewed-счётчики severity (critical/high/medium/low)
   из data.reviewSummary.

Никаких UI/веб-серверов не запускай. Накопительный журнал (`journal-update`) в
этом headless-пайплайне НЕ ведётся — кросс-ран состояние отслеживает API.

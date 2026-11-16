#!/usr/bin/env python3
"""Проверки BSL-модуля, которые не требуют платформы 1С.

Что проверяется:

* файл читается как UTF-8, без BOM (вставка такого файла в конфигуратор
  ломается на первом символе);
* парность блоков: Процедура/КонецПроцедуры, Функция/КонецФункции,
  Если/КонецЕсли (препроцессорные #Если не считаются), Для|Пока/КонецЦикла,
  Попытка/КонецПопытки;
* число экспортных методов, если ожидание передано явно (--expect-exports);
* в тексте нет токенов, паролей, приватных ключей и адресов почты;
* если задан --tag, версия из шапки модуля совпадает с тегом (v1.0.1 → 1.0.1).

Чего не делает: не проверяет типы, не знает контекста платформы и не заменяет
синтаксический контроль конфигурации. Строковые литералы при подсчёте блоков
не разбираются — ключевое слово внутри строки в кавычках может дать ложное
срабатывание; для модулей без таких строк это несущественно.

Запуск:
    python3 .github/check_bsl.py src/*.bsl [--expect-exports 43] [--tag v1.0.1]
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

BLOCK_PAIRS = [
    ("Процедура", "КонецПроцедуры"),
    ("Функция", "КонецФункции"),
    ("Если", "КонецЕсли"),
    ("Попытка", "КонецПопытки"),
]

SECRET_PATTERNS = [
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub personal access token"),
    (r"gho_[A-Za-z0-9]{20,}", "GitHub OAuth token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained token"),
    (r"sk-[A-Za-z0-9]{20,}", "API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"https?://[^/\s:@]+:[^/\s@]+@", "credentials in URL"),
    (r"(?i)(пароль|password|passwd|token|secret)\s*=\s*[\"'][^\"']{4,}", "hardcoded credential"),
    (r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}", "email address"),
]

EXPORT_RE = re.compile(r"(?im)^\s*(?:Процедура|Функция)\s+([A-Za-zА-Яа-яЁё_][\wА-Яа-яЁё]*)\s*\([^)]*\)\s*Экспорт")
VERSION_RE = re.compile(r"(?im)^\s*//.*?Версия\s+(\d+\.\d+\.\d+)")


def strip_comment(line: str) -> str:
    """Убрать строчный комментарий (//), не трогая содержимое кавычек."""
    out, in_str = [], False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            in_str = not in_str
        if not in_str and line.startswith("//", i):
            break
        out.append(ch)
        i += 1
    return "".join(out)


def read_source(path: pathlib.Path) -> tuple[str, list[str]]:
    raw = path.read_bytes()
    problems: list[str] = []
    if raw.startswith(b"\xef\xbb\xbf"):
        problems.append("файл начинается с BOM: 1С не примет такой модуль при вставке")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{path}: не UTF-8 ({exc})") from exc
    return text, problems


def check_blocks(path: pathlib.Path, text: str) -> list[str]:
    problems: list[str] = []
    opens = {"Процедура": 0, "Функция": 0, "Если": 0, "Попытка": 0, "Цикл": 0}
    closes = {"КонецПроцедуры": 0, "КонецФункции": 0, "КонецЕсли": 0, "КонецПопытки": 0, "КонецЦикла": 0}
    for lineno, line in enumerate(text.splitlines(), 1):
        code = strip_comment(line).strip()
        if not code or code.startswith("#"):
            continue
        match = re.match(r"[A-Za-zА-Яа-яЁё_][\wА-Яа-яЁё]*", code)
        if not match:
            continue
        word = match.group(0)
        if word in ("Процедура", "Функция", "Попытка"):
            opens[word] += 1
        elif word == "Если":
            # «ИначеЕсли» отдельным словом не приходит, но и не считается
            opens["Если"] += 1
        elif word in ("Для", "Пока"):
            opens["Цикл"] += 1
        elif word in closes:
            closes[word] += 1
        if word in closes and closes[word] > sum(
            opens[k] for k in {"КонецПроцедуры": ("Процедура",), "КонецФункции": ("Функция",),
                               "КонецЕсли": ("Если",), "КонецПопытки": ("Попытка",),
                               "КонецЦикла": ("Цикл",)}[word]
        ):
            problems.append(f"строка {lineno}: {word} без открывающего блока")
    for opener, closer in BLOCK_PAIRS:
        if opens[opener] != closes[closer]:
            problems.append(f"{opener}={opens[opener]}, {closer}={closes[closer]} — блоки не парные")
    for_opener = opens["Цикл"]
    if for_opener != closes["КонецЦикла"]:
        problems.append(f"Для/Пока={for_opener}, КонецЦикла={closes['КонецЦикла']} — блоки не парные")
    return problems


def check_secrets(path: pathlib.Path, text: str) -> list[str]:
    problems: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                problems.append(f"строка {lineno}: похоже на {label}")
    return problems


def check_version(path: pathlib.Path, text: str, tag: str) -> list[str]:
    match = VERSION_RE.search(text)
    if not match:
        return ["в шапке модуля нет строки «Версия X.Y.Z»"]
    module_version = match.group(1)
    tag_version = tag.lstrip("vV")
    if module_version != tag_version:
        return [f"версия в шапке {module_version} не совпадает с тегом {tag}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверки BSL без платформы 1С")
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    parser.add_argument("--expect-exports", type=int, default=None,
                        help="ожидаемое число экспортных методов; расхождение — предупреждение")
    parser.add_argument("--strict-exports", action="store_true",
                        help="считать расхождение в --expect-exports ошибкой")
    parser.add_argument("--tag", default=None, help="тег релиза, напр. v1.0.1")
    args = parser.parse_args(argv)

    failures = 0
    total_exports = 0
    for path in args.files:
        if not path.is_file():
            print(f"✗ {path}: файл не найден")
            failures += 1
            continue
        text, problems = read_source(path)
        problems += check_blocks(path, text)
        problems += check_secrets(path, text)
        if args.tag:
            problems += check_version(path, text, args.tag)
        exports = EXPORT_RE.findall(text)
        total_exports += len(exports)
        status = "✓" if not problems else "✗"
        print(f"{status} {path}: {len(text.splitlines())} строк, экспортных методов {len(exports)}")
        for problem in problems:
            print(f"    {problem}")
        failures += bool(problems)

    if args.expect_exports is not None:
        if total_exports == args.expect_exports:
            print(f"✓ экспортных методов {total_exports}, как и заявлено")
        elif args.strict_exports:
            print(f"✗ экспортных методов {total_exports}, ожидалось {args.expect_exports}")
            failures += 1
        else:
            print(f"! экспортных методов {total_exports}, в ожидании {args.expect_exports} — "
                  f"обновите число в workflow и README (мягкий режим, проверка не падает)")

    if failures:
        print(f"\nПроверка не пройдена: {failures} проблем(ы)")
        return 1
    print("\nПроверка пройдена")
    return 0


if __name__ == "__main__":
    sys.exit(main())

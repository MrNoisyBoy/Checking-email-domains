#!/usr/bin/env python3
"""
Email Domain & SMTP Verification Tool
Проверка валидности email через MX-записи и SMTP-handshake
"""

import re
import socket
import smtplib
import dns.resolver
import dns.exception
from dataclasses import dataclass
from typing import List, Optional, Tuple
from email.utils import parseaddr
import argparse
import sys


@dataclass
class VerificationResult:
    email: str
    status: str
    details: str
    mx_record: Optional[str] = None
    smtp_code: Optional[int] = None


class EmailVerifier:
    def __init__(
            self,
            timeout: int = 10,
            sender_email: str = "verify@example.com",
            verbose: bool = False
    ):
        self.timeout = timeout
        self.sender_email = sender_email
        self.verbose = verbose
        self.email_regex = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            re.IGNORECASE
        )

    def _validate_syntax(self, email: str) -> bool:
        """Проверка синтаксиса email."""
        return bool(self.email_regex.match(email))

    def _get_mx_records(self, domain: str) -> List[str]:
        """Получение MX-записей домена."""
        try:
            answers = dns.resolver.resolve(domain, 'MX', lifetime=self.timeout)
            # Сортируем по приоритету (preference)
            records = sorted(
                [(r.preference, str(r.exchange).rstrip('.')) for r in answers],
                key=lambda x: x[0]
            )
            return [r[1] for r in records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            if self.verbose:
                print(f"DNS Error for {domain}: {e}")
            return []

    def _check_smtp(self, email: str, mx_host: str) -> Tuple[int, str]:
        """
        SMTP-handshake без отправки письма.
        Используем RCPT TO для проверки существования ящика.
        """
        try:
            # Пробуем подключиться к 25 порту (стандартный SMTP)
            server = smtplib.SMTP(timeout=self.timeout)
            server.connect(mx_host, 25)

            if self.verbose:
                server.set_debuglevel(1)

            # Получаем локальный hostname для HELO
            host = socket.getfqdn()

            # SMTP-диалог
            server.helo(host)
            server.mail(self.sender_email)
            code, message = server.rcpt(email)
            server.quit()

            return code, message.decode() if isinstance(message, bytes) else str(message)

        except (socket.timeout, socket.error, ConnectionRefusedError) as e:
            # Пробуем альтернативный порт 587 (STARTTLS) если 25 закрыт
            try:
                server = smtplib.SMTP(timeout=self.timeout)
                server.connect(mx_host, 587)
                host = socket.getfqdn()
                server.helo(host)
                server.mail(self.sender_email)
                code, message = server.rcpt(email)
                server.quit()
                return code, message.decode() if isinstance(message, bytes) else str(message)
            except Exception as e2:
                return -1, f"Connection failed: {e2}"
        except smtplib.SMTPException as e:
            return -1, f"SMTP error: {e}"
        except Exception as e:
            return -1, f"Unexpected error: {e}"

    def verify(self, email: str) -> VerificationResult:
        """
        Полная проверка email:
        1. Синтаксис
        2. MX-записи домена
        3. SMTP-handshake (RCPT TO)
        """
        email = email.strip().lower()

        # Шаг 1: Синтаксис
        if not self._validate_syntax(email):
            return VerificationResult(
                email=email,
                status="INVALID_SYNTAX",
                details="Некорректный формат email адреса"
            )

        # Извлекаем домен
        _, addr = parseaddr(email)
        if '@' not in addr:
            addr = email
        try:
            domain = addr.split('@')[1]
        except IndexError:
            return VerificationResult(
                email=email,
                status="INVALID_SYNTAX",
                details="Не удалось извлечь домен из адреса"
            )

        # Шаг 2: MX-записи
        mx_records = self._get_mx_records(domain)
        if not mx_records:
            # Проверяем, существует ли домен вообще (A-запись)
            try:
                dns.resolver.resolve(domain, 'A', lifetime=self.timeout)
                return VerificationResult(
                    email=email,
                    status="NO_MX_RECORDS",
                    details="Домен существует, но MX-записи отсутствуют или некорректны"
                )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return VerificationResult(
                    email=email,
                    status="DOMAIN_NOT_FOUND",
                    details="Домен не существует (NXDOMAIN)"
                )
            except Exception:
                return VerificationResult(
                    email=email,
                    status="NO_MX_RECORDS",
                    details="MX-записи отсутствуют или некорректны"
                )

        primary_mx = mx_records[0]

        # Шаг 3: SMTP-проверка
        code, message = self._check_smtp(email, primary_mx)

        if code == 250:
            status = "VALID"
            details = f"Email существует (SMTP: {code})"
        elif code in (550, 551, 553, 554):
            status = "INVALID_RECIPIENT"
            details = f"Ящик не существует или отклонен (SMTP: {code} - {message})"
        elif code == 252:
            status = "UNCERTAIN"
            details = f"Невозможно верифицировать (SMTP: {code} - сервер принимает все)"
        elif code == -1:
            status = "SMTP_ERROR"
            details = f"Ошибка соединения: {message}"
        else:
            status = "UNCERTAIN"
            details = f"Неоднозначный ответ сервера (SMTP: {code} - {message})"

        return VerificationResult(
            email=email,
            status=status,
            details=details,
            mx_record=primary_mx,
            smtp_code=code
        )

    def verify_batch(self, emails: List[str]) -> List[VerificationResult]:
        """Пакетная проверка с обработкой ошибок."""
        results = []
        for email in emails:
            try:
                result = self.verify(email)
                results.append(result)
            except Exception as e:
                results.append(VerificationResult(
                    email=email,
                    status="ERROR",
                    details=f"Критическая ошибка: {str(e)}"
                ))
        return results


def format_status(status: str) -> str:
    """Цветовое форматирование статуса (если поддерживается терминал)."""
    colors = {
        "VALID": "\033[92m✓ ДОМЕН ВАЛИДЕН\033[0m",
        "DOMAIN_NOT_FOUND": "\033[91m✗ ДОМЕН ОТСУТСТВУЕТ\033[0m",
        "NO_MX_RECORDS": "\033[93m⚠ MX-ЗАПИСИ ОТСУТСТВУЮТ\033[0m",
        "INVALID_SYNTAX": "\033[91m✗ НЕКОРРЕКТНЫЙ ФОРМАТ\033[0m",
        "INVALID_RECIPIENT": "\033[91m✗ ЯЩИК НЕ СУЩЕСТВУЕТ\033[0m",
        "SMTP_ERROR": "\033[93m⚠ ОШИБКА SMTP\033[0m",
        "UNCERTAIN": "\033[94m? НЕОДНОЗНАЧНО\033[0m",
        "ERROR": "\033[91m✗ ОШИБКА\033[0m"
    }
    return colors.get(status, status)


def main():
    parser = argparse.ArgumentParser(
        description="Проверка валидности email-адресов через MX и SMTP"
    )
    parser.add_argument(
        'emails',
        nargs='+',
        help='Email-адреса для проверки'
    )
    parser.add_argument(
        '--sender', '-s',
        default='verify@example.com',
        help='Email отправителя для SMTP-handshake (default: verify@example.com)'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=10,
        help='Таймаут соединения в секундах (default: 10)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Подробный вывод SMTP-диалога'
    )
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Вывод в формате JSON'
    )

    args = parser.parse_args()

    verifier = EmailVerifier(
        timeout=args.timeout,
        sender_email=args.sender,
        verbose=args.verbose
    )

    results = verifier.verify_batch(args.emails)

    if args.json:
        import json
        output = [
            {
                "email": r.email,
                "status": r.status,
                "details": r.details,
                "mx_record": r.mx_record,
                "smtp_code": r.smtp_code
            }
            for r in results
        ]
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(f"\n{'=' * 70}")
        print(f"{'EMAIL':<30} {'СТАТУС':<25} {'ДЕТАЛИ'}")
        print(f"{'=' * 70}")

        for r in results:
            status_display = format_status(r.status)
            print(f"{r.email:<30} {status_display:<25} {r.details}")

            if r.mx_record and args.verbose:
                print(f"{'':30} MX: {r.mx_record}")

        print(f"{'=' * 70}")

        # Сводка
        valid = sum(1 for r in results if r.status == "VALID")
        print(f"\nИтого: {len(results)} проверено, {valid} валидных")


if __name__ == "__main__":
    main()
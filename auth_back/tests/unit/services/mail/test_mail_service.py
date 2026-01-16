from collections.abc import Iterator
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import BackgroundTasks
from fastapi_mail import MessageType
import pytest

from app.exceptions.email import FailedSendingEmailException
from app.services.mail.mail import (
    MailBodySchema,
    MailTaskSchema,
    MailType,
    send_email_event,
    send_forgot_email,
    send_verify_email,
)

if TYPE_CHECKING:
    from pydantic import EmailStr


# Фикстура для мока FastMail
@pytest.fixture
def mock_fastmail() -> Iterator[AsyncMock]:
    """Мокает объект FastMail для отправки писем."""
    with patch("app.services.mail.mail.fm") as mock_fm:
        mock_fm.send_message = AsyncMock()
        yield mock_fm


# Фикстура для BackgroundTasks
@pytest.fixture
def bg_tasks() -> BackgroundTasks:
    """Создает объект BackgroundTasks для тестов."""
    return BackgroundTasks()


######################### ТЕСТЫ send_verify_email ########################


@pytest.mark.asyncio
async def test_send_verify_email(bg_tasks: BackgroundTasks, mock_fastmail: AsyncMock) -> None:
    """Тестирует добавление задачи отправки письма для верификации email."""
    recipients: list[EmailStr] = ["test@example.com"]
    token = "test-token"

    # Вызываем функцию
    send_verify_email(recipients=recipients, token=token, bg_task=bg_tasks)

    # Проверяем, что задача добавлена
    assert len(bg_tasks.tasks) == 1
    task = bg_tasks.tasks[0]
    task_func = task.func
    task_args = task.args

    # Проверяем, что задача вызывает send_email_event с правильными параметрами
    assert task_func == send_email_event
    mail_task = cast("MailTaskSchema", task_args[0])
    assert mail_task.recipients == recipients
    assert mail_task.body.type == MailType.VERIFY
    assert mail_task.body.token == token
    assert mail_task.body.url == "/verify-email?t="


######################### ТЕСТЫ send_forgot_email ########################


@pytest.mark.asyncio
async def test_send_forgot_email(bg_tasks: BackgroundTasks, mock_fastmail: AsyncMock) -> None:
    """Тестирует добавление задачи отправки письма для сброса пароля."""
    recipients = ["test@example.com"]
    token = "test-token"

    # Вызываем функцию
    send_forgot_email(recipients=recipients, token=token, bg_task=bg_tasks)

    # Проверяем, что задача добавлена
    assert len(bg_tasks.tasks) == 1
    task = bg_tasks.tasks[0]
    task_func = task.func
    task_args = task.args

    # Проверяем, что задача вызывает send_email_event с правильными параметрами
    assert task_func == send_email_event
    mail_task = cast("MailTaskSchema", task_args[0])
    assert mail_task.recipients == recipients
    assert mail_task.body.type == MailType.RESET_PASSWORD
    assert mail_task.body.token == token
    assert mail_task.body.url == "/reset-password?t="


######################### ТЕСТЫ send_email_event ########################


@pytest.mark.asyncio
async def test_send_email_event_verify(mock_fastmail: AsyncMock) -> None:
    """Тестирует отправку письма для верификации email."""
    mail_task = MailTaskSchema(
        recipients=["test@example.com"],
        body=MailBodySchema(
            type=MailType.VERIFY,
            token="test-token",
            url="/verify?t=",
        ),
    )

    # Мокаем settings.FRONTEND_URL
    with patch("app.services.mail.mail.settings", new=MagicMock(FRONTEND_URL="http://frontend.com")):
        await send_email_event(mail_task)

    # Проверяем, что send_message вызван с правильными параметрами
    mock_fastmail.send_message.assert_awaited_once()
    call_args = mock_fastmail.send_message.call_args[0][0]
    assert call_args.subject == "Подтверждение регистрации"
    assert [r.email for r in call_args.recipients] == mail_task.recipients
    assert call_args.subtype == MessageType.html
    assert "http://frontend.com/verify?t=test-token" in call_args.body


@pytest.mark.asyncio
async def test_send_email_event_reset_password(mock_fastmail: AsyncMock) -> None:
    """Тестирует отправку письма для сброса пароля."""
    mail_task = MailTaskSchema(
        recipients=["test@example.com"],
        body=MailBodySchema(
            type=MailType.RESET_PASSWORD,
            token="test-token",
            url="/reset-password?t=",
        ),
    )

    # Мокаем settings.FRONTEND_URL
    with patch("app.services.mail.mail.settings", new=MagicMock(FRONTEND_URL="http://frontend.com")):
        await send_email_event(mail_task)

    # Проверяем, что send_message вызван с правильными параметрами
    mock_fastmail.send_message.assert_awaited_once()
    call_args = mock_fastmail.send_message.call_args[0][0]
    assert call_args.subject == "Сброс пароля"
    assert [r.email for r in call_args.recipients] == mail_task.recipients
    assert call_args.subtype == MessageType.html
    assert "http://frontend.com/reset-password" in call_args.body


@pytest.mark.asyncio
async def test_send_email_event_notification(mock_fastmail: AsyncMock) -> None:
    """Тестирует отправку письма-уведомления."""
    mail_task = MailTaskSchema(
        recipients=["test@example.com"],
        body=MailBodySchema(
            type=MailType.NOTIFICATION,
            message="Test notification message",
        ),
    )

    # Мокаем settings.FRONTEND_URL
    with patch("app.services.mail.mail.settings", new=MagicMock(FRONTEND_URL="http://frontend.com")):
        await send_email_event(mail_task)

    # Проверяем, что send_message вызван с правильными параметрами
    mock_fastmail.send_message.assert_awaited_once()
    call_args = mock_fastmail.send_message.call_args[0][0]
    assert call_args.subject == "Уведомление"
    assert [r.email for r in call_args.recipients] == mail_task.recipients
    assert call_args.subtype == MessageType.html
    assert call_args.body == ""


@pytest.mark.asyncio
async def test_send_email_event_failure(mock_fastmail: AsyncMock) -> None:
    """Тестирует обработку ошибки при отправке письма."""
    mail_task = MailTaskSchema(
        recipients=["test@example.com"],
        body=MailBodySchema(
            type=MailType.VERIFY,
            token="test-token",
            url="/verify?t=",
        ),
    )

    # Мокаем ошибку в send_message
    mock_fastmail.send_message.side_effect = Exception("SMTP error")

    # Проверяем, что выбрасывается FailedSendingEmail
    with patch("app.services.mail.mail.settings", new=MagicMock(FRONTEND_URL="http://frontend.com")):
        with pytest.raises(FailedSendingEmailException) as exc:
            await send_email_event(mail_task)
    assert exc.value.status_code == 500
    assert "Failed" in exc.value.detail

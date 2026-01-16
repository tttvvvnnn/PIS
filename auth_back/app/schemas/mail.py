from enum import Enum

from pydantic import BaseModel, EmailStr


class MailType(str, Enum):
    """
    Enum класс для типа письма.

    :cvar str VERIFY: Верификация почты нового пользователя.
    :cvar str RESET_PASSWORD: Сброс пароля по почте.
    :cvar str NOTIFICATION: Уведомление от приложения.
    """

    VERIFY = "verify"
    RESET_PASSWORD = "reset_password"
    NOTIFICATION = "notification"


class MailBodySchema(BaseModel):
    """
    Тело письма.

    :cvar MailType type: Тип письма (VERIFY, RESET_PASSWORD, NOTIFICATION).
    :cvar str | None token: Токен для верификации или сброса пароля.
    :cvar str | None url: URL ведущая на фронтенд.
    :cvar str | None message: Текст уведомления.
    """

    type: MailType
    token: str | None = None  # Для верификации или сброса пароля
    url: str = ""
    message: str | None = None  # Для уведомлений


class MailTaskSchema(BaseModel):
    """
    Задача отправки письма.

    :cvar list[EmailStr] recipients: Список адресов получателей.
    :cvar MailBodySchema body: Тело письма.
    """

    recipients: list[EmailStr]
    body: MailBodySchema

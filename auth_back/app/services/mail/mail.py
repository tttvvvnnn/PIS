from typing import TYPE_CHECKING, cast

from fastapi import BackgroundTasks
from fastapi_mail import MessageSchema, MessageType, MultipartSubtypeEnum
from pydantic import EmailStr

from app.core.config import settings
from app.core.email_config import JINJA_ENV, fm
from app.exceptions.email import FailedSendingEmailException
from app.schemas.mail import MailBodySchema, MailTaskSchema, MailType

if TYPE_CHECKING:
    from fastapi_mail import NameEmail


def send_verify_email(recipients: list[EmailStr], token: str, bg_task: BackgroundTasks) -> None:
    """
    Добавляет задачу отправки письма для верификации email в фоновый режим.

    :param recipients: Список адресов получателей.
    :param  token: Верификационный токен.
    :param bg_task: Объект для фоновых задач.
    """
    mail_task = MailTaskSchema(
        recipients=recipients,
        body=MailBodySchema(
            type=MailType.VERIFY,
            token=token,
            url=settings.VERIFY_URL,
        ),
    )
    bg_task.add_task(send_email_event, mail_task)


def send_forgot_email(recipients: list[EmailStr], token: str, bg_task: BackgroundTasks) -> None:
    """
    Добавляет задачу отправки письма для сброса пароля.

    :param recipients: Список адресов получателей.
    :param  token: Верификационный токен.
    :param bg_task: Объект для фоновых задач.
    """
    mail_task = MailTaskSchema(
        recipients=recipients,
        body=MailBodySchema(
            type=MailType.RESET_PASSWORD,
            token=token,
            url=settings.FORGOT_PASSWORD_URL,
        ),
    )
    bg_task.add_task(send_email_event, mail_task)


async def send_email_event(mail_task: MailTaskSchema) -> None:
    """
    Отправляет письмо для верификации email в фоновом режиме.

    :param mail_task: Получатели, тело письма.
    :raises: FailedSendingEmail: Если не удалось отправить письмо.
    """
    try:
        url = settings.FRONTEND_URL + mail_task.body.url + f"{mail_task.body.token}"

        if mail_task.body.type == MailType.VERIFY:
            html_template = JINJA_ENV.get_template("verify_email.html")
            text_template = JINJA_ENV.get_template("verify_email.txt")
            subject = "Подтверждение регистрации"
        elif mail_task.body.type == MailType.RESET_PASSWORD:
            html_template = JINJA_ENV.get_template("reset_password.html")
            text_template = JINJA_ENV.get_template("reset_password.txt")
            subject = "Сброс пароля"
        else:
            html_template = JINJA_ENV.get_template("notification.html")
            text_template = JINJA_ENV.get_template("notification.txt")
            subject = "Уведомление"

        html_body = html_template.render(url=url)
        text_body = text_template.render(url=url)

        message = MessageSchema(
            subject=subject,
            recipients=cast("list[NameEmail]", mail_task.recipients),
            body=html_body,
            subtype=MessageType.html,
            alternative_body=text_body,
            multipart_subtype=MultipartSubtypeEnum.alternative,
        )

        await fm.send_message(message)
    except Exception as e:
        raise FailedSendingEmailException from e

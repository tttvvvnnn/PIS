from starlette.status import (
    HTTP_422_UNPROCESSABLE_CONTENT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.exceptions.base import AppHTTPException


class FailedSendingEmailException(AppHTTPException):
    """Ошибка при отправке письма."""

    status_code = HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Failed to send email"
    example = {"detail": "Failed to send email"}


class EmailDomainNotFoundException(AppHTTPException):
    """Исключение, если домен email не имеет MX-записи."""

    status_code = HTTP_422_UNPROCESSABLE_CONTENT
    detail = "Email domain does not exist or no MX record found"
    example = {"detail": "Email domain does not exist or no MX record found"}


class EmailMismatchException(AppHTTPException):
    """Email в запросе не совпадает с email авторизованного пользователя."""

    status_code = HTTP_422_UNPROCESSABLE_CONTENT
    detail = "Email does not match the authenticated user's email"
    example = {"detail": "Email does not match the authenticated user's email"}

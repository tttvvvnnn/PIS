from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_422_UNPROCESSABLE_CONTENT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.exceptions.base import AppHTTPException


class WrongRoleException(AppHTTPException):
    """Нет данной роли в БД."""

    status_code = HTTP_422_UNPROCESSABLE_CONTENT
    detail = "Role {role} is not valid"
    example = {"detail": "Role {role} is not valid"}

    def __init__(self, role: str) -> None:
        """
        Инициализация деталей исключения.

        :param role: Роль.
        """
        super().__init__(detail=self.detail.format(role=role))


class MissingRoleException(AppHTTPException):
    """Роль не указана в токене."""

    status_code = HTTP_422_UNPROCESSABLE_CONTENT
    detail = "Role is missing"
    example = {"detail": "Role is missing"}


class WrongPasswordException(AppHTTPException):
    """Пользователь ввёл неверный пароль."""

    status_code = HTTP_401_UNAUTHORIZED
    detail = "Wrong password"
    example = {"detail": "Wrong password"}
    headers = {"WWW-Authenticate": "Bearer"}


class InvalidTokenException(AppHTTPException):
    """Невалидный токен."""

    status_code = HTTP_401_UNAUTHORIZED
    detail = "Invalid token"
    example = {"detail": "Invalid token"}
    headers = {"WWW-Authenticate": "Bearer"}


class ExpiredTokenException(AppHTTPException):
    """Истек срок действия токена."""

    status_code = HTTP_401_UNAUTHORIZED
    detail = "Expired token"
    example = {"detail": "Expired token"}
    headers = {"WWW-Authenticate": "Bearer"}


class TokenBlackListCreationException(AppHTTPException):
    """Внутренняя ошибка создания токена."""

    status_code = HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Failed to black listen token"
    example = {"detail": "Failed to black listen token"}


class RightsException(AppHTTPException):
    """Недостаточно прав у пользователя."""

    status_code = HTTP_403_FORBIDDEN
    detail = "Insufficient permissions"
    example = {"detail": "Insufficient permissions"}

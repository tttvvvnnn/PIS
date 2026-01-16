from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.exceptions.base import AppHTTPException


class UserAlreadyExistsException(AppHTTPException):
    """Исключение, когда пользователь пытается зарегистрироваться с email, который уже есть в БД."""

    status_code = HTTP_409_CONFLICT
    detail = "A user with this email already exists"
    example = {"detail": "A user with this email already exists"}


class UserCreationException(AppHTTPException):
    """Не получилось создать пользователя в БД."""

    status_code = HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Failed to create user"
    example = {"detail": "Failed to create user"}


class UserUpdateException(AppHTTPException):
    """Не получилось обновить данные о пользователе в БД."""

    status_code = HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Failed to update user"
    example = {"detail": "Failed to update user"}


class UserNotFoundException(AppHTTPException):
    """Нет пользователя с таким email."""

    status_code = HTTP_404_NOT_FOUND
    detail = "User is not found"
    example = {"detail": "User is not found"}


class UserVerifiedException(AppHTTPException):
    """Пользователь уже верифицирован."""

    status_code = HTTP_409_CONFLICT
    detail = "User is already verified"
    example = {"detail": "User is already verified"}


class UserNotVerifiedException(AppHTTPException):
    """Пользователь не подтвердил почту по ссылке в письме."""

    status_code = HTTP_403_FORBIDDEN
    detail = "Access is forbidden. Verify your email"
    example = {"detail": "Access is forbidden. Verify your email"}


class SamePasswordException(AppHTTPException):
    """Пользователь пытается обновить пароль на такой же."""

    status_code = HTTP_400_BAD_REQUEST
    detail = "New password must be different from the old one"
    example = {"detail": "New password must be different from the old one"}

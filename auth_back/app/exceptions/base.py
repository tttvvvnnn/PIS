from fastapi import HTTPException
from starlette.status import HTTP_400_BAD_REQUEST


class AppHTTPException(HTTPException):
    """
    Базовый класс для пользовательских HTTP-исключений приложения.

    :cvar int status_code: Код ошибки из библиотеки starlette
    :cvar str detail: Описание ошибки
    :cvar dict example: Пример возвращаемой ошибки
    :cvar dict[str, str]: HTTP-заголовки для ответа.
    """

    status_code: int = HTTP_400_BAD_REQUEST
    detail: str = "An error occurred"
    example: dict[str, str] = {"detail": "An error occurred"}
    headers: dict[str, str] = {}

    def __init__(
        self,
        status_code: int | None = None,
        detail: str | None = None,
        example: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """
        Инициализация исключения.

        :param status_code: HTTP-код состояния.
        :param detail: Описание ошибки.
        :param example: Пример ответа для документации.
        :param headers: HTTP-заголовки для ответа.
        """
        super().__init__(
            status_code=status_code or self.status_code, detail=detail or self.detail, headers=headers or self.headers
        )
        self.example = example or self.example

from pydantic import BaseModel


class SuccessResponse(BaseModel):
    """
    Ответ с сообщением об успешной операции.

    :cvar str msg: Сообщение об успехе.
    """

    msg: str

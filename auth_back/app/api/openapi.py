from typing import Any

from app.exceptions.base import AppHTTPException


def generate_responses(*exceptions: type[AppHTTPException]) -> dict[int | str, dict[str, Any]]:
    """
    Генерирует словарь с примерами ответов для документации OpenAPI из списка классов исключений.

    :param exceptions: Классы исключений, унаследованные от AppHTTPException.
    :return: Словарь для параметра `responses` в декораторе FastAPI.
    """
    responses: dict[int | str, dict[str, Any]] = {}
    for exc in exceptions:
        status_code = exc.status_code
        # Если статус-кода еще нет, создаем базовую структуру
        if status_code not in responses:
            responses[status_code] = {
                "description": exc.detail,
                "content": {"application/json": {"examples": {}}},
            }

        response_name = exc.__name__.replace("Exception", "")
        example_data: dict[str, Any] = {"summary": exc.detail, "value": exc.example}

        responses[status_code]["content"]["application/json"]["examples"][response_name] = example_data

    # Если мы сгенерировали ответы для кода 422, объединим их со стандартной схемой
    if 422 in responses:
        # Прямо указываем ссылку на стандартную схему ошибки валидации FastAPI
        responses[422]["content"]["application/json"]["schema"] = {"$ref": "#/components/schemas/HTTPValidationError"}

        # Добавляем пример дефолтной ошибки валидации
        validation_error_example: dict[str, Any] = {
            "summary": "Validation Error",
            "value": {
                "detail": [{"loc": ["body", "field_name"], "msg": "field required", "type": "value_error.missing"}]
            },
        }
        responses[422]["content"]["application/json"]["examples"]["ValidationError"] = validation_error_example

    return responses

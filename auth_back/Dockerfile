# Используем официальный легкий образ Python
FROM python:3.11-slim

# Устанавливаем переменные окружения для Python
# PYTHONDONTWRITEBYTECODE 1 - не создавать .pyc файлы
# PYTHONUNBUFFERED 1 - вывод логов сразу в консоль
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Переменные для Poetry
    POETRY_VERSION=2.0.0 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false

# Добавляем poetry в PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Устанавливаем системные зависимости (curl нужен для установки poetry)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Устанавливаем рабочую директорию
WORKDIR /auth_back

# Копируем сначала файлы конфигурации (для кэширования слоев Docker)
COPY pyproject.toml poetry.lock ./

# Устанавливаем зависимости проекта
# --no-root означает "не устанавливать сам наш проект как пакет", только библиотеки
RUN poetry install --no-root --no-interaction --no-ansi

# Теперь копируем весь остальной код приложения
COPY . .

# Команда запуска (используем shell-форму, чтобы переменные подставились если нужно)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
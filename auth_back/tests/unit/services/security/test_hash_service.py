from app.services.security.hash import get_password_hash, verify_password

######################### ТЕСТЫ verify_password ########################


def test_verify_password_correct() -> None:
    """Успешная верификация пароля."""
    hashed_password = get_password_hash("password123")

    assert verify_password("password123", hashed_password) is True


def test_verify_password_incorrect() -> None:
    """Верификация неверного пароля."""
    hashed_password = get_password_hash("password123")

    assert verify_password("wrongpassword", hashed_password) is False


######################### ТЕСТЫ get_password_hash ########################


def test_get_password_hash() -> None:
    """Проверка успешного хеширования пароля."""
    password = "password123"
    hashed = get_password_hash(password)

    assert isinstance(hashed, str)
    assert verify_password(password, hashed) is True

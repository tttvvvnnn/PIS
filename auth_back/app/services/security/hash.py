from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


def get_password_hash(password: str) -> str:
    """
    Хеширование пароля с использованием Argon2.

    :param password: Пароль для хеширования.
    :return: Захешированный пароль.
    :rtype: Str
    """
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет, соответствует ли захешированный пришедший пароль захешированному в БД.

    :param plain_password: Пароль, введенный пользователем.
    :param hashed_password: Захешированный пароль из базы данных.
    :return: Соответствует ли пароль захешированному.
    :rtype: Bool
    """
    return password_hash.verify(plain_password, hashed_password)

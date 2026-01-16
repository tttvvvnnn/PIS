# authService

```
cinema_auth_service/
├── auth_back/
│   ├── app/
│   │   ├── api/                # HTTP-роутеры (auth, users)
│   │   ├── core/               # Конфигурация, settings, security
│   │   ├── db/                 # Работа с БД
│   │   │   ├── crud/           # CRUD-операции
│   │   │   └── models/         # SQLAlchemy модели
│   │   ├── schemas/            # Pydantic-схемы
│   │   ├── services/           # Бизнес-логика (auth, users, jwt)
│   │   └── main.py             # Точка входа FastAPI
│   │
│   ├── tests/                  # Unit и integration тесты
│   ├── migrations/             # Миграции базы данных
│   ├── .env                    # Переменные окружения
│   ├── docker-compose.yml
│   └── Dockerfile
│
├── auth_front/
│   ├── index.html              # UI (login / signup / logout)
│   ├── styles.css              # Стили
│   ├── app.js                  # Логика запросов к API
│   ├── nginx.conf              # Конфигурация nginx
│   └── Dockerfile              # Сборка фронтенда
│
└── Makefile
```
### Запустить код

```shell
docker compose up -d --build
```

Frontend: (http://localhost:3000)    
Почтовый ящик: (http://localhost:8025)    
Документация backend-а: (http://localhost:8000/docs)

### БД

### Миграции базы данных

Создание миграции:
```bash
docker compose exec app alembic revision --autogenerate -m "migration name"
```
Применение миграции:
```bash
docker compose exec app alembic upgrade head
```


Заполнение бд ролями:
```sql
INSERT INTO user_role (name) VALUES 
    ('user'),
    ('admin'),
    ('moderator');
```
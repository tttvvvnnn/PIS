BACK_COMPOSE = auth_back/docker-compose.yml
FRONT_COMPOSE = auth_front/docker-compose.yml

# ==============================================================================
# DOCKER MANAGEMENT
# ==============================================================================

up:
	@echo "--- Run Backend ---"
	docker compose -f $(BACK_COMPOSE) up -d --build
	@echo "--- Backend is set up. Run Frontend... ---"
	docker compose -f $(FRONT_COMPOSE) up -d --build
	@echo "--- Everything is running! ---"

# Остановка всего
down:
	@echo "--- Stop Frontend ---"
	docker compose -f $(FRONT_COMPOSE) down
	@echo "--- Stop Backend ---"
	docker compose -f $(BACK_COMPOSE) down

# Пересборка (если нужно принудительно без кэша)
rebuild:
	@echo "--- Rebuild Backend ---"
	docker compose -f $(BACK_COMPOSE) build --no-cache
	@echo "--- Rebuild Frontend ---"
	docker compose -f $(FRONT_COMPOSE) build --no-cache
	$(MAKE) up

# ==============================================================================
# DATABASE MIGRATIONS
# ==============================================================================

generate:
	@echo "--- Upgrading database migration... ---"
	docker compose -f auth_back/docker-compose.yml exec app alembic -c alembic.ini revision --autogenerate -m ""


migrate:
	@echo "--- Upgrading database migration... ---"
	docker compose -f auth_back/docker-compose.yml exec app alembic -c alembic.ini upgrade head

downgrade:
	@echo "--- Downgrading database migration... ---"
	docker compose -f auth_back/docker-compose.yml exec app alembic -c alembic.ini downgrade -1

# ==============================================================================
# TESTING
# ==============================================================================

test:
	@echo "Running local tests..."
	cd auth_back && 	poetry run pytest -v --cov=app --cov-report=html --cov-report=xml --cov-report=term-missing --cov-fail-under=90 tests

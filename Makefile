.PHONY: install run test lint format security check

install:
	python -m pip install -r requirements-dev.txt

run:
	python -m src.backend.run

test:
	python -m pytest -q --cov=src/backend --cov-report=term-missing

lint:
	python -m ruff check src tests
	python -m black --check src tests

format:
	python -m ruff check --fix src tests
	python -m black src tests

security:
	python -m bandit -r src/backend -ll

check: lint security test

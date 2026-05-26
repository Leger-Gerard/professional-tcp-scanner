.PHONY: help install dev-test test lint format type-check clean build docker-build docker-run

help:
	@echo "TCP Port Scanner - Development Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make install        Install package in development mode"
	@echo "  make dev-test       Run tests with coverage"
	@echo "  make test           Run tests only"
	@echo "  make lint           Check code style with ruff"
	@echo "  make format         Fix code style with ruff"
	@echo "  make type-check     Run mypy type checking"
	@echo "  make clean          Remove build artifacts"
	@echo "  make build          Build distributable package"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-run     Run containerized scanner"
	@echo ""

install:
	pip install -e .

dev-test:
	pip install -e ".[dev]"
	python -m pytest tests/ --cov=src --cov-report=term-missing

test:
	python -m pytest tests/

lint:
	ruff check src tests

format:
	ruff check --fix src tests

type-check:
	mypy src

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache/ htmlcov/ .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[co]" -delete

build:
	python -m build

docker-build:
	docker build -t port-scanner .

docker-run:
	docker run --rm port-scanner $(filter-out $@,$(MAKECMDGOALS))

# Allow passing arguments to docker-run
%:
	@:
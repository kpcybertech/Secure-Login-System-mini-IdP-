.PHONY: venv dev test cov

venv:
	python -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip

dev:
	. .venv/bin/activate && pip install -r requirements-dev.txt

test:
	. .venv/bin/activate && pytest -q

cov:
	. .venv/bin/activate && pytest --cov=. --cov-report=term-missing

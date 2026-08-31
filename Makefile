PY ?= python3

.PHONY: test lint check clean

## run the test suite (from the repo root so the tests package is importable)
test:
	$(PY) -m unittest discover -v

## byte-compile the package and syntax-check the remote script
lint:
	$(PY) -m py_compile $$(find sshaudit bin -name '*.py')
	bash -n remote/enum.sh

check: lint test

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete

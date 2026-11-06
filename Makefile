.PHONY: test-unit test-integration

test-unit:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/unit

test-integration:
	PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/integration

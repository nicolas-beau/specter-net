.PHONY: install test lint docker clean

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

lint:
	flake8 specter_net/ --max-line-length=120

docker:
	docker build -t specter-net .

docker-run:
	docker compose up -d

clean:
	rm -rf __pycache__ .pytest_cache

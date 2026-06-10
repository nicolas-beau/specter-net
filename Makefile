.PHONY: install test lint docker
install:
	pip install -r requirements.txt
test:
	pytest tests/ -v
lint:
	flake8 specter_net/ --max-line-length=120
docker:
	docker build -t specter-net .

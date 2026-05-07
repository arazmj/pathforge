.PHONY: up down logs test build smoke

build:
cargo build --release

smoke: build
python3 tests/smoke_test.py

test:
cargo test

up:
docker compose up --build -d

down:
docker compose down -v

logs:
docker compose logs -f

e2e:
bash tests/e2e.sh

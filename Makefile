.PHONY: build run clean install test docker-build docker-run

# Default target
build:
	shards build --release

# Development build
dev:
	shards build

# Install dependencies
install:
	shards install

# Run the application
run:
	./bin/summaly

# Run in development mode
dev-run:
	crystal run src/main.cr

# Clean build artifacts
clean:
	rm -rf bin/ lib/ .shards/

# Run tests
test:
	crystal spec

# Docker build
docker-build:
	docker build -t summaly-cr .

# Docker run
docker-run:
	docker run -p 12267:12267 summaly-cr

# Format code
format:
	crystal tool format

# Check for issues
lint:
	crystal tool format --check

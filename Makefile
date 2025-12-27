.PHONY: build run test clean deps

# Build the server
build:
	go build -o bin/server ./cmd/server

# Build a specific function
build-function:
	@if [ -z "$(FUNCTION)" ]; then echo "Usage: make build-function FUNCTION=<name>"; exit 1; fi
	go build -o bin/functions/$(FUNCTION) ./functions/$(FUNCTION)

# Build all functions
build-functions:
	@for dir in functions/*/; do \
		name=$$(basename $$dir); \
		echo "Building $$name..."; \
		go build -o bin/functions/$$name ./functions/$$name; \
	done

# Run the server locally
run:
	go run ./cmd/server

# Run tests
test:
	go test -v ./...

# Download dependencies
deps:
	go mod download
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/

# Create a new function
new-function:
	@if [ -z "$(NAME)" ]; then echo "Usage: make new-function NAME=<function-name>"; exit 1; fi
	mkdir -p functions/$(NAME)
	cp functions/hello/main.go functions/$(NAME)/main.go
	@echo "Created new function: functions/$(NAME)"
	@echo "Edit functions/$(NAME)/main.go to implement your function"

.PHONY: test

test:
	@echo "Running tests..."
	@go test ./... -v -coverprofile=coverage.out -covermode=atomic
	@go tool cover -func=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Tests completed."
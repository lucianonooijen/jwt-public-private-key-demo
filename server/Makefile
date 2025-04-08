help: ## Shows all commands
	@echo 'All Makefile commands:'
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


.PHONY: run
run: ## Runs the application without hot reloading
	go run .

.PHONY: test
test: ## Runs the unit tests
	go test ./...


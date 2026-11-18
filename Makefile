.PHONY: help test lint check-scripts chmodx

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

test:  ## Run the Python test suite
	pytest -q

lint:  ## Lint Python (ruff) and bash (shellcheck), as CI does
	ruff check .
	find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 shellcheck

check-scripts:  ## Syntax-check every bash script in the repo
	@for f in $$(find . -name '*.sh' -not -path './.git/*'); do \
		echo "checking $$f"; bash -n "$$f"; \
	done

chmodx:  ## Make all bash scripts executable (set the +x bit in git)
	@for f in $$(find . -name '*.sh' -not -path './.git/*'); do \
		git update-index --chmod=+x "$$f" 2>/dev/null || true; \
	done
	@echo "done."

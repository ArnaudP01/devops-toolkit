.PHONY: help test check-scripts chmodx

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

test:  ## Run the Python test suite
	pytest -q

check-scripts:  ## Syntax-check every bash script
	@for f in scripts/bash/*.sh; do echo "checking $$f"; bash -n "$$f"; done

chmodx:  ## Make all bash scripts executable (set the +x bit in git)
	@for f in scripts/bash/*.sh; do git update-index --chmod=+x "$$f" 2>/dev/null || true; done
	@echo "done."

help:
	@echo "make help      - Show this help"
	@echo "make dev       - Creates the development environment"
	@echo "make docs      - Build the documentation"
	@echo "make view-docs - View the documentation"
	@echo "make clean     - Delete all untracked/ignored files and directories"

dev:
	pip install -r requirements.txt
	pip install -e .

docs:
	make -C docs html

view-docs: docs
	open docs/_build/html/index.html

clean:
	git ls-files --other --directory | xargs rm -rf

.PHONY: help dev docs view-docs clean

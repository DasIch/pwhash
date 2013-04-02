help:
	@echo "make help      - Show this help"
	@echo "make docs      - Build the documentation"
	@echo "make view-docs - View the documentation"
	@echo "make clean     - Delete all untracked/ignored files and directories"

docs:
	make -C docs html

view-docs: docs
	open docs/_build/html/index.html

clean:
	git ls-files --other --directory | xargs rm -rf

.PHONY: help docs view-docs clean

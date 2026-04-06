.PHONY: clean help

clean:
	find . -name '*.pyc' -delete
	find . -name '*.pyo' -delete
	find . -name '*~' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +

help:
	@echo "    clean"
	@echo "        Remove python artifacts and __pycache__ directories."
.PHONY: clean help sync sync-dry sync-wireless sync-printer sync-firewall sync-industrial sync-wordlist

clean:
	find . -name '*.pyc' -delete
	find . -name '*.pyo' -delete
	find . -name '*~' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +

## Sync from specialized XPL Suite tools into EmbedXPL
sync:
	python -m embedxpl.tools.sync_from_suite --target all --check-imports

sync-dry:
	python -m embedxpl.tools.sync_from_suite --target all --dry-run --verbose

sync-wireless:
	python -m embedxpl.tools.sync_from_suite --target wireless --verbose

sync-printer:
	python -m embedxpl.tools.sync_from_suite --target printer --verbose

sync-firewall:
	python -m embedxpl.tools.sync_from_suite --target firewall --verbose

sync-industrial:
	python -m embedxpl.tools.sync_from_suite --target industrial --verbose

sync-wordlist:
	python -m embedxpl.tools.sync_from_suite --target wordlist --verbose

help:
	@echo "    clean"
	@echo "        Remove python artifacts and __pycache__ directories."
	@echo "    sync"
	@echo "        Sync all specialized XPL Suite tools into EmbedXPL."
	@echo "    sync-dry"
	@echo "        Preview sync without writing files."
	@echo "    sync-wireless / sync-printer / sync-firewall / sync-industrial / sync-wordlist"
	@echo "        Sync a single specialized tool."
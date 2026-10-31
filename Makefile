.PHONY: app release gui test

app:
	./scripts/build_macos_app.sh

release:
	./package_release_dmg.sh

gui:
	./run_debug.sh

test:
	./.venv/bin/python -m unittest discover -v

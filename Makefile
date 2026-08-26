.PHONY: app release gui test

app:
	./scripts/build_macos_app.sh

release:
	./package_release_dmg.sh

gui:
	./.venv/bin/python main.py --gui

test:
	./.venv/bin/python -m unittest discover -v

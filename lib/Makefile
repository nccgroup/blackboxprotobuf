all: test_py2 test_py3
setup_py2:
	rm -rf /tmp/bbpb-python2-tmp
	python2 -m virtualenv /tmp/bbpb-python2-tmp
	. /tmp/bbpb-python2-tmp/bin/activate
	python2 -m pip install -r tests/requirements-python2-dev.txt
test_py2: setup_py2
	python2 -m pytest tests/
test_py3:
	poetry env use python3
	poetry run python -m pytest tests/
format:
	poetry run black .

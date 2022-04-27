VERSION:=$(shell python setup.py --version)

install:
	python setup.py install
	$(info ahihi)

uninstall:
	pip uninstall cicflowmeter -y

clean:
	rm -rf *.egg-info build dist report.xml

build:
	python setup.py sdist bdist_wheel --universal

release:
	@git tag -a v$(VERSION)
	@git push --tag

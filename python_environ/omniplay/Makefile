
.PHONY: all install clean
all: parseklograwmodule.c setup.py ${OMNIPLAY_DIR}/test/libutil.a
	python setup.py build

install: setup.py
	python setup.py install

clean:
	rm -rf build


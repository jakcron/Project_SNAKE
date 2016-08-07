main: build

rebuild: clean build

build:
	cd lib && $(MAKE) && cd ..
	cd src && $(MAKE) && cd ..

clean:
	cd lib && $(MAKE) clean && cd ..
	cd src && $(MAKE) clean && cd ..
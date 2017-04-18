LIBS = fnd crypto yaml keystore nintendo es ctr
main: build

rebuild: clean build

build:
	@$(foreach lib,$(LIBS), cd $(lib) && $(MAKE) && cd ..;)

clean:
	@$(foreach lib,$(LIBS), cd $(lib) && $(MAKE) clean && cd ..;)
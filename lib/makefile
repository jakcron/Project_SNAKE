LIBS = fnd crypto yaml es oschar rvl ctr keystore
main: build

rebuild: clean build

build:
	@$(foreach lib,$(LIBS), cd $(lib) && $(MAKE) && cd ..;)

clean:
	@$(foreach lib,$(LIBS), cd $(lib) && $(MAKE) clean && cd ..;)
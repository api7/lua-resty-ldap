### dev:          Install runtime dependencies locally
.PHONY: dev
dev:
	luarocks install rockspec/lua-resty-ldap-main-0.rockspec --only-deps --local

### test:         Run the test suite
.PHONY: test
test:
	git apply t/patch/unknown_op.patch
	prove -r t/
	git apply t/patch/unknown_op.patch -R

### help:         Show Makefile rules
.PHONY: help
help:
	@echo Makefile rules:
	@echo
	@grep -E '^### [-A-Za-z0-9_]+:' Makefile | sed 's/###/   /'

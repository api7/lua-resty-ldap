PREFIX ?=          /usr/local/openresty
LUA_LIB_DIR ?=     $(PREFIX)/lualib/$(LUA_VERSION)
INSTALL ?= install

### install:      Install the library to runtime
.PHONY: install
install:
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/resty/ldap/
	$(INSTALL) lib/resty/*.lua $(DESTDIR)/$(LUA_LIB_DIR)/resty/ldap/

### dev:          Create a development ENV
.PHONY: dev
dev:
	luarocks install rockspec/lua-resty-ldap-main-0.1-0.rockspec --only-deps --local

### help:         Show Makefile rules
.PHONY: help
help:
	@echo Makefile rules:
	@echo
	@grep -E '^### [-A-Za-z0-9_]+:' Makefile | sed 's/###/   /'

test:
	prove -r t/

LOG		:= meta-source/debian/changelog
META_NAME	:= $(shell head -n 1 $(LOG) | sed 's/\(.*\)[[:space:]]\+(.*).*/\1/')
META_VERSION	:= $(shell head -n 1 $(LOG) | sed 's/.*(\(.*\)).*/\1/')
META_SERIES	:= $(shell head -n 1 $(LOG) | sed 's/.*(.*)[[:space:]]\+\(.*\);.*/\1/' | sed 's/-.*//')
LAST_VERSION	?= $(shell rmadison -a source -s $(META_SERIES)-updates $(META_NAME) | cut -d '|' -f 2 | tr -d '[:blank:]')

ifeq ($(LAST_VERSION),)
LAST_VERSION	:= $(shell rmadison -a source -s $(META_SERIES) $(META_NAME) | cut -d '|' -f 2 | tr -d '[:blank:]')
ifeq ($(LAST_VERSION),)
LAST_VERSION	:= $(META_VERSION)
endif
endif

all: source

source: clean
	ln -s meta-source $(META_NAME)-$(META_VERSION)
	cd $(META_NAME)-$(META_VERSION); \
	dpkg-buildpackage -S -sa -rfakeroot -I.git -I.gitignore -i'\.git.*' -v$(LAST_VERSION)

binary: clean
	ln -s meta-source $(META_NAME)-$(META_VERSION)
	cd $(META_NAME)-$(META_VERSION); \
	debuild -b

clean:
	cd meta-source && fakeroot debian/rules clean
	rm -f $(META_NAME)-$(META_VERSION)
	rm -f *.dsc *.changes *.gz *.deb *.build *.upload


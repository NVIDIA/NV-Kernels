LOG		:= meta-source/debian/changelog
META_VERSION	:= $(shell head -1 $(LOG)|sed 's/.*(\(.*\)).*/\1/')

all: source

source: clean
	ln -s meta-source linux-ports-$(META_VERSION)
	cd linux-ports-$(META_VERSION); \
	dpkg-buildpackage -S -sa -rfakeroot -I.git -I.gitignore -i'\.git.*'

binary: clean
	ln -s meta-source linux-ports-$(META_VERSION)
	cd linux-ports-$(META_VERSION); \
	debuild -b

clean:
	cd meta-source && fakeroot debian/rules clean
	rm -f linux-ports-$(META_VERSION)
	rm -f *.dsc *.changes *.gz *.deb *.build


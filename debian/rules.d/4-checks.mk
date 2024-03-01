# Check the signature of staging modules
module-signature-check-%: $(stampdir)/stamp-install-%
	@echo Debug: $@
	$(DROOT)/scripts/module-signature-check "$*" \
		"$(DROOT)/$(mods_pkg_name)-$*" \
		"$(DROOT)/$(mods_extra_pkg_name)-$*"

checks-%: module-signature-check-%
	@echo Debug: $@

# Check the config against the known options list.
config-prepare-check-%: $(stampdir)/stamp-prepare-tree-%
	@echo Debug: $@
	if [ -e $(commonconfdir)/config.common.ubuntu ]; then \
		perl -f $(DROOT)/scripts/config-check \
			$(builddir)/build-$*/.config "$(arch)" "$*" "$(commonconfdir)" \
			"$(skipconfig)" "$(do_enforce_all)"; \
	else \
		python3 $(DROOT)/scripts/misc/annotations -f $(commonconfdir)/annotations \
			--arch $(arch) --flavour $* --check $(builddir)/build-$*/.config; \
	fi

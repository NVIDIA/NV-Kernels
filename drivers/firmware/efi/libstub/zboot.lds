/* SPDX-License-Identifier: GPL-2.0 */

ENTRY(__efistub_efi_zboot_header);

PROVIDE(zboot_code_size = ABSOLUTE(0));

SECTIONS
{
	.head : ALIGN(4096) {
		*(.head)
	}

	.text : {
		*(.text* .init.text*)
	}

	.rodata : ALIGN(8) {
		__efistub__gzdata_start = .;
		*(.gzdata)
		__efistub_payload_size = . - 4;
		__efistub__gzdata_end = .;
		*(.rodata* .init.rodata* .srodata*)

		. = ALIGN(4);
		__efistub_code_size = .;
		LONG(zboot_code_size);

		_etext = ALIGN(4096);
		. = _etext;
	}

        .sbat : ALIGN(4096) {
		_sbat = .;
		*(.sbat)
		_esbat = ALIGN(4096);
		. = _esbat;
	}

	.data : ALIGN(4096) {
		_data = .;
		*(.data* .init.data*)
		_edata = ALIGN(512);
		. = _edata;
	}

	.bss : {
		*(.bss* .init.bss*)
		_end = ALIGN(512);
		. = _end;
	}

	/DISCARD/ : {
		*(.discard .discard.*)
		*(.modinfo .init.modinfo)
	}
}

PROVIDE(__efistub__gzdata_size =
		ABSOLUTE(__efistub__gzdata_end - __efistub__gzdata_start));

PROVIDE(__data_rawsize = ABSOLUTE(_edata - _data));
PROVIDE(__data_size = ABSOLUTE(_end - _data));
PROVIDE(__sbat_size = ABSOLUTE(_esbat - _sbat));

/*
 * ARM64_SECURE_LAUNCH references these __efistub_ aliases, but sl_entry
 * is not reachable in the compressed zboot path, so a drtm=on zboot build
 * silently no-ops the DRTM launch. These stubs only let such a build link.
 */
PROVIDE_HIDDEN(__efistub__text    = ADDR(.head));
PROVIDE_HIDDEN(__efistub__end     = _end);
PROVIDE_HIDDEN(__efistub__edata   = _edata);
PROVIDE_HIDDEN(__efistub_sl_entry = ADDR(.head));

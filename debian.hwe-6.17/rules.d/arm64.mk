build_arch	= arm64
defconfig	= defconfig
flavours	= generic generic-64k
build_image	= Image.gz
kernel_file	= arch/$(build_arch)/boot/Image.gz
install_file	= vmlinuz
no_dumpfile = true
uefi_signed     = true

vdso		= vdso_install

do_tools_usbip  = true
do_tools_cpupower = true
do_tools_perf   = true
do_tools_perf_jvmti = true
do_tools_perf_python = true
do_tools_bpftool = true
do_tools_rtla = true

do_dtbs		= true
do_extras_package = true
do_tools_noble_hwe = true
gcc		= gcc-13
rustc		= rustc-1.82
rustfmt		= /usr/lib/rust-1.82/bin/rustfmt
bindgen		= bindgen-0.65

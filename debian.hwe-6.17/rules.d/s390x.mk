build_arch      = s390
defconfig       = defconfig
flavours        = generic
build_image	= bzImage
kernel_file	= arch/$(build_arch)/boot/bzImage
install_file	= vmlinuz

vdso		= vdso_install
no_dumpfile	= true

sipl_signed       = true
do_tools_usbip    = true
do_tools_cpupower = true
do_tools_perf     = true
do_tools_perf_jvmti = true
do_tools_perf_python = true
do_tools_bpftool  = true
do_tools_rtla = false
do_extras_package = true
do_tools_noble_hwe = true
gcc		= gcc-13
rustc		= rustc-1.82
rustfmt		= /usr/lib/rust-1.82/bin/rustfmt
bindgen		= bindgen-0.65

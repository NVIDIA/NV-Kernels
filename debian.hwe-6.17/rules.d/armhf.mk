build_arch	= arm
defconfig	= defconfig
flavours	= generic
build_image	= zImage
kernel_file	= arch/$(build_arch)/boot/zImage
install_file	= vmlinuz
no_dumpfile	= true

do_tools_usbip  = true
do_tools_cpupower = true
do_tools_perf	= false
do_tools_perf_jvmti = false
do_tools_perf_python = false
do_tools_bpftool = true
do_tools_bpftool_stub = true
do_tools_rtla = true

do_dtbs		= true
do_tools_noble_hwe = true
gcc		= gcc-13
rustc		= rustc-1.82
rustfmt		= /usr/lib/rust-1.82/bin/rustfmt
bindgen		= bindgen-0.65

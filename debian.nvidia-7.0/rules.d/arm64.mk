build_arch	= arm64
defconfig	= defconfig
flavours	= nvidia nvidia-64k
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
do_tools_noble_hwe = true

do_dtbs		= true

do_lib_rust             = false
gcc                     = gcc-13
rustc                   = rustc-1.80
rustfmt                 = /usr/lib/rust-1.80/bin/rustfmt
bindgen                 = bindgen-0.65

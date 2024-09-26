human_arch	= 64 bit x86
build_arch	= x86
defconfig	= defconfig
flavours	= nvidia-adv
build_image	= bzImage
kernel_file	= arch/$(build_arch)/boot/bzImage
install_file	= vmlinuz
no_dumpfile	= true

vdso		= vdso_install

do_extras_package = true
do_tools_usbip  = true
do_tools_cpupower = true
do_tools_perf   = true
do_tools_perf_jvmti = true
do_tools_perf_python = true
do_tools_bpftool = true
do_tools_rtla = true
do_lib_rust     = false

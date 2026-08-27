// SPDX-License-Identifier: GPL-2.0
/*
 * Kexec image loader

 * Copyright (C) 2018 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 */

#define pr_fmt(fmt)	"kexec_file(Image): " fmt

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/pe.h>
#include <linux/string.h>
#include <asm/byteorder.h>
#include <asm/cpufeature.h>
#include <asm/image.h>
#include <asm/memory.h>
#include <asm/drtm.h>
#include <linux/arm-smccc.h>

static int image_probe(const char *kernel_buf, unsigned long kernel_len)
{
	const struct arm64_image_header *h =
		(const struct arm64_image_header *)(kernel_buf);

	if (!h || (kernel_len < sizeof(*h)))
		return -EINVAL;

	if (memcmp(&h->magic, ARM64_IMAGE_MAGIC, sizeof(h->magic)))
		return -EINVAL;

	return 0;
}

static void *image_load(struct kimage *image,
				char *kernel, unsigned long kernel_len,
				char *initrd, unsigned long initrd_len,
				char *cmdline, unsigned long cmdline_len)
{
	struct arm64_image_header *h;
	u64 flags, value;
	bool be_image, be_kernel;
	struct kexec_buf kbuf = {};
	unsigned long text_offset, kernel_segment_number;
	struct kexec_segment *kernel_segment;
	int ret;

	/*
	 * We require a kernel with an unambiguous Image header. Per
	 * Documentation/arch/arm64/booting.rst, this is the case when image_size
	 * is non-zero (practically speaking, since v3.17).
	 */
	h = (struct arm64_image_header *)kernel;
	if (!h->image_size)
		return ERR_PTR(-EINVAL);

	/* Check cpu features */
	flags = le64_to_cpu(h->flags);
	if (arm64_image_flag_field(flags, ARM64_IMAGE_FLAG_SECURE_LAUNCH) && h->res4)
		image->arch.drtm_sl_entry_offset = le64_to_cpu(h->res4);
	else
		image->arch.drtm_sl_entry_offset = 0;
	be_image = arm64_image_flag_field(flags, ARM64_IMAGE_FLAG_BE);
	be_kernel = IS_ENABLED(CONFIG_CPU_BIG_ENDIAN);
	if ((be_image != be_kernel) && !system_supports_mixed_endian())
		return ERR_PTR(-EINVAL);

	value = arm64_image_flag_field(flags, ARM64_IMAGE_FLAG_PAGE_SIZE);
	if (((value == ARM64_IMAGE_FLAG_PAGE_SIZE_4K) &&
			!system_supports_4kb_granule()) ||
	    ((value == ARM64_IMAGE_FLAG_PAGE_SIZE_64K) &&
			!system_supports_64kb_granule()) ||
	    ((value == ARM64_IMAGE_FLAG_PAGE_SIZE_16K) &&
			!system_supports_16kb_granule()))
		return ERR_PTR(-EINVAL);

	/* Load the kernel */
	kbuf.image = image;
	kbuf.buf_min = 0;
	kbuf.buf_max = ULONG_MAX;
	kbuf.top_down = false;

	kbuf.buffer = kernel;
	kbuf.bufsz = kernel_len;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	kbuf.memsz = le64_to_cpu(h->image_size);
	text_offset = le64_to_cpu(h->text_offset);
	kbuf.buf_align = MIN_KIMG_ALIGN;

	/* Adjust kernel segment with TEXT_OFFSET */
	kbuf.memsz += text_offset;

	if (cmdline && strstr(cmdline, "drtm=on")) {
		struct arm_smccc_res res;
		unsigned long dlme_size;
		u32 dlme_pages, nw_dce_pages;

		if (!image->arch.drtm_sl_entry_offset) {
			pr_warn("kexec_file_load: drtm=on requested, but target kernel does not advertise DRTM Secure Launch capability (flags bit 4 / res4 offset). Falling back to normal boot without DRTM.\n");
			goto out_normal_boot;
		}

		/* Query D-CRTM (TF-A) for DLME minimum memory requirement */
		arm_smccc_smc(DRTM_SMC_FEATURES,
				  DRTM_FEAT_QUERY_64BIT | DRTM_FEAT_MEM_REQ,
				  0, 0, 0, 0, 0, 0, &res);
		if ((s64)res.a0 > 0) {
			dlme_pages = (u32)res.a1;
			nw_dce_pages = (u32)(res.a1 >> 32);
			if (nw_dce_pages) {
				pr_warn("kexec_file_load: DRTM requested a %u-page Normal-world DCE region, which is not supported. Falling back to normal boot without DRTM.\n",
					nw_dce_pages);
				goto out_normal_boot;
			}

			dlme_size = (unsigned long)dlme_pages * DRTM_PAGE_SIZE;
			pr_info("kexec_file: DRTM SMC requested %lu bytes for DLME data\n",
				dlme_size);
		} else {
			pr_warn("kexec_file_load: drtm=on requested, but active TF-A returned SMCCC_NOT_SUPPORTED (%lld). Falling back to normal boot without DRTM.\n",
				(s64)res.a0);
			goto out_normal_boot;
		}

		image->arch.secure_launch = true;
		image->arch.drtm_dlme_size = dlme_size;
		kbuf.memsz += SL_DLME_DTB_SLOT_GAP + dlme_size;
	}
out_normal_boot:
	kernel_segment_number = image->nr_segments;

	/*
	 * The location of the kernel segment may make it impossible to satisfy
	 * the other segment requirements, so we try repeatedly to find a
	 * location that will work.
	 */
	while ((ret = kexec_add_buffer(&kbuf)) == 0) {
		/* Try to load additional data */
		kernel_segment = &image->segment[kernel_segment_number];
		ret = load_other_segments(image, kernel_segment->mem,
					  kernel_segment->memsz, initrd,
					  initrd_len, cmdline);
		if (!ret)
			break;

		/*
		 * We couldn't find space for the other segments; erase the
		 * kernel segment and try the next available hole.
		 */
		image->nr_segments -= 1;
		kbuf.buf_min = kernel_segment->mem + kernel_segment->memsz;
		kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	}

	if (ret) {
		pr_err("Could not find any suitable kernel location!");
		return ERR_PTR(ret);
	}

	kernel_segment = &image->segment[kernel_segment_number];
	kernel_segment->mem += text_offset;
	kernel_segment->memsz -= text_offset;
	image->start = kernel_segment->mem;

	kexec_dprintk("Loaded kernel at 0x%lx bufsz=0x%lx memsz=0x%lx\n",
		      kernel_segment->mem, kbuf.bufsz,
		      kernel_segment->memsz);

	return NULL;
}

const struct kexec_file_ops kexec_image_ops = {
	.probe = image_probe,
	.load = image_load,
#ifdef CONFIG_KEXEC_IMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};

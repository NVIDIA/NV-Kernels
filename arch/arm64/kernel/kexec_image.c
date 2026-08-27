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

enum image_drtm_policy {
	IMAGE_DRTM_OFF,
	IMAGE_DRTM_ON,
	IMAGE_DRTM_ENFORCE,
};

static enum image_drtm_policy image_drtm_policy(const char *cmdline)
{
	enum image_drtm_policy policy = IMAGE_DRTM_OFF;
	const char *p = cmdline;

	if (!p)
		return policy;

	while (*p) {
		const char *end;
		size_t len;

		while (*p == ' ' || *p == '\t')
			p++;
		end = p;
		while (*end && *end != ' ' && *end != '\t')
			end++;
		len = end - p;

		if (len == sizeof("drtm=off") - 1 &&
		    !memcmp(p, "drtm=off", len))
			policy = IMAGE_DRTM_OFF;
		else if (len == sizeof("drtm=on") - 1 &&
			 !memcmp(p, "drtm=on", len))
			policy = IMAGE_DRTM_ON;
		else if (len == sizeof("drtm=enforce") - 1 &&
			 !memcmp(p, "drtm=enforce", len))
			policy = IMAGE_DRTM_ENFORCE;

		p = end;
	}

	return policy;
}

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
	unsigned long text_offset, kernel_segment_number, normal_memsz;
	struct kexec_segment *kernel_segment;
	enum image_drtm_policy drtm_policy;
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
	normal_memsz = kbuf.memsz;

	drtm_policy = image_drtm_policy(cmdline);
	if (drtm_policy != IMAGE_DRTM_OFF) {
		struct arm_smccc_res res;
		unsigned long dlme_size;
		u32 dlme_pages, nw_dce_pages;
		const char *policy_name = drtm_policy == IMAGE_DRTM_ENFORCE ?
			"enforce" : "on";

		if (!image->arch.drtm_sl_entry_offset) {
			pr_warn("drtm=%s requested, but the target kernel does not advertise DRTM Secure Launch capability\n",
				policy_name);
			if (drtm_policy == IMAGE_DRTM_ENFORCE)
				return ERR_PTR(-EOPNOTSUPP);
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
				pr_warn("DRTM requested an unsupported %u-page Normal-world DCE region\n",
					nw_dce_pages);
				if (drtm_policy == IMAGE_DRTM_ENFORCE)
					return ERR_PTR(-EOPNOTSUPP);
				goto out_normal_boot;
			}

			dlme_size = (unsigned long)dlme_pages * DRTM_PAGE_SIZE;
			pr_info("kexec_file: DRTM SMC requested %lu bytes for DLME data\n",
				dlme_size);
		} else {
			pr_warn("drtm=%s requested, but DRTM_FEATURES failed (%lld)\n",
				policy_name,
				(s64)res.a0);
			if (drtm_policy == IMAGE_DRTM_ENFORCE)
				return ERR_PTR(-EOPNOTSUPP);
			goto out_normal_boot;
		}

		image->arch.secure_launch = true;
		image->arch.drtm_enforce =
			drtm_policy == IMAGE_DRTM_ENFORCE;
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

	if (ret && image->arch.secure_launch &&
	    !image->arch.drtm_enforce) {
		pr_warn("DRTM image placement failed; retrying a normal boot\n");
		image->arch.secure_launch = false;
		image->arch.drtm_dlme_size = 0;
		kbuf.buf_min = 0;
		kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
		kbuf.memsz = normal_memsz;
		goto out_normal_boot;
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

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 */
#ifndef __EROFS_FS_COMPRESS_H
#define __EROFS_FS_COMPRESS_H

#include "internal.h"

struct z_erofs_decompress_req {
	struct super_block *sb;
	struct page **in, **out;
	unsigned short pageofs_in, pageofs_out;
	unsigned int inputsize, outputsize;

	unsigned int alg;       /* the algorithm for decompression */
	bool inplace_io, partial_decoding, fillgaps;
	gfp_t gfp;      /* allocation flags for extra temporary buffers */
};

struct z_erofs_decompressor {
	int (*config)(struct super_block *sb, struct erofs_super_block *dsb,
		      void *data, int size);
	int (*decompress)(struct z_erofs_decompress_req *rq,
			  struct page **pagepool);
	char *name;
};

#define Z_EROFS_SHORTLIVED_PAGE		(-1UL << 2)
#define Z_EROFS_PREALLOCATED_FOLIO	((void *)(-2UL << 2))

/*
 * short-lived pages are pages directly from buddy system with specific
 * page->private (no need to set PagePrivate since these are non-LRU /
 * non-movable pages and bypass reclaim / migration code).
 */
static inline bool z_erofs_is_shortlived_page(struct page *page)
{
	if (page->private != Z_EROFS_SHORTLIVED_PAGE)
		return false;

	DBG_BUGON(page->mapping);
	return true;
}

static inline bool z_erofs_put_shortlivedpage(struct page **pagepool,
					      struct page *page)
{
	if (!z_erofs_is_shortlived_page(page))
		return false;

	/* short-lived pages should not be used by others at the same time */
	if (page_ref_count(page) > 1) {
		put_page(page);
	} else {
		/* follow the pcluster rule above. */
		erofs_pagepool_add(pagepool, page);
	}
	return true;
}

#define MNGD_MAPPING(sbi)	((sbi)->managed_cache->i_mapping)
static inline bool erofs_page_is_managed(const struct erofs_sb_info *sbi,
					 struct page *page)
{
	return page->mapping == MNGD_MAPPING(sbi);
}

int z_erofs_fixup_insize(struct z_erofs_decompress_req *rq, const char *padbuf,
			 unsigned int padbufsize);
extern const struct z_erofs_decompressor erofs_decompressors[];

/* prototypes for specific algorithms */
int z_erofs_load_lzma_config(struct super_block *sb,
			struct erofs_super_block *dsb, void *data, int size);
int z_erofs_load_deflate_config(struct super_block *sb,
			struct erofs_super_block *dsb, void *data, int size);
int z_erofs_lzma_decompress(struct z_erofs_decompress_req *rq,
			    struct page **pagepool);
int z_erofs_deflate_decompress(struct z_erofs_decompress_req *rq,
			       struct page **pagepool);
#endif

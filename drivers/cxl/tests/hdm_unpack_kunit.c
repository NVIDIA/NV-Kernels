// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
#include <kunit/test.h>
#include <linux/bitfield.h>
#include <linux/sizes.h>

#include "cxl.h"
#include "../core/core.h"

static void cxl_hdm_unpack_test(struct kunit *test)
{
	static const struct {
		const char *name;
		u32 ctrl;
		u64 base;
		u64 size;
		int rc;
		unsigned long flags;
		int ways;
		int granularity;
		enum cxl_decoder_type target_type;
	} cases[] = {
		{ "valid", CXL_HDM_DECODER0_CTRL_COMMITTED,
		  SZ_1G, SZ_256M, 0, CXL_DECODER_F_ENABLE,
		  1, 256, CXL_DECODER_DEVMEM },
		{ "overflow", CXL_HDM_DECODER0_CTRL_COMMITTED,
		  U64_MAX - 127, 256, -ENXIO },
		{ "all-ones base", CXL_HDM_DECODER0_CTRL_COMMITTED,
		  U64_MAX, SZ_256M, -ENXIO },
		{ "last address", CXL_HDM_DECODER0_CTRL_COMMITTED,
		  U64_MAX - 255, 256, 0, CXL_DECODER_F_ENABLE,
		  1, 256, CXL_DECODER_DEVMEM },
		{ "zero size", CXL_HDM_DECODER0_CTRL_COMMITTED,
		  SZ_1G, 0, 0, CXL_DECODER_F_ENABLE,
		  1, 256, CXL_DECODER_DEVMEM },
		{ "uncommitted stale size", 0,
		  SZ_1G, SZ_256M, 0, 0, 1, 256 },
		{ "locked host-only interleave",
		  CXL_HDM_DECODER0_CTRL_COMMITTED | CXL_HDM_DECODER0_CTRL_LOCK |
		  CXL_HDM_DECODER0_CTRL_HOSTONLY |
		  FIELD_PREP_CONST(CXL_HDM_DECODER0_CTRL_IW_MASK, 10) |
		  FIELD_PREP_CONST(CXL_HDM_DECODER0_CTRL_IG_MASK, 2),
		  SZ_1G, SZ_256M, 0, CXL_DECODER_F_ENABLE | CXL_DECODER_F_LOCK,
		  12, SZ_1K, CXL_DECODER_HOSTONLYMEM },
	};

	for (int i = 0; i < ARRAY_SIZE(cases); i++) {
		struct cxl_decoder_config config;
		u64 size;
		int rc;

		rc = cxl_hdm_unpack_decoder(&config, 3, cases[i].ctrl,
					    cases[i].base, cases[i].size);
		KUNIT_EXPECT_EQ_MSG(test, rc, cases[i].rc, "%s", cases[i].name);
		if (rc || rc != cases[i].rc)
			continue;
		size = cases[i].size;
		if (!(cases[i].flags & CXL_DECODER_F_ENABLE))
			size = 0;
		KUNIT_EXPECT_EQ_MSG(test, config.id, 3, "%s", cases[i].name);
		KUNIT_EXPECT_EQ_MSG(test, config.hpa_range.start, cases[i].base,
				    "%s", cases[i].name);
		KUNIT_EXPECT_EQ_MSG(test, range_len(&config.hpa_range), size,
				    "%s", cases[i].name);
		KUNIT_EXPECT_EQ_MSG(test, config.flags, cases[i].flags,
				    "%s", cases[i].name);
		KUNIT_EXPECT_EQ_MSG(test, config.interleave_ways, cases[i].ways,
				    "%s", cases[i].name);
		KUNIT_EXPECT_EQ_MSG(test, config.interleave_granularity,
				    cases[i].granularity, "%s", cases[i].name);
		/* An uncommitted decoder has no meaningful target type. */
		if (cases[i].flags & CXL_DECODER_F_ENABLE)
			KUNIT_EXPECT_EQ_MSG(test, config.target_type,
					    cases[i].target_type, "%s", cases[i].name);
	}
}

static struct kunit_case cxl_hdm_test_cases[] = {
	KUNIT_CASE(cxl_hdm_unpack_test),
	{}
};

static struct kunit_suite cxl_hdm_test_suite = {
	.name = "cxl-hdm-unpack",
	.test_cases = cxl_hdm_test_cases,
};

kunit_test_suite(cxl_hdm_test_suite);

MODULE_DESCRIPTION("KUnit tests for CXL HDM decoder unpacking");
MODULE_LICENSE("GPL");

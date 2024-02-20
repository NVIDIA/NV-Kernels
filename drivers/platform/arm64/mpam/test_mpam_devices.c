// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 Arm Ltd.
/* This file is intended to be included into mpam_devices.c */

#include <kunit/test.h>

static void test_mpam_extend_config(struct kunit *test)
{
	struct mpam_config fake_cfg = { 0 };
	struct mpam_class fake_class = { 0 };

	/* Configurations with both are not modified */
	fake_class.props.bwa_wd = 16;
	fake_cfg.mbw_max = 0xfeef;
	fake_cfg.mbw_min = 0xfeef;
	fake_cfg.features = 0;
	mpam_set_feature(mpam_feat_mbw_max, &fake_cfg);
	mpam_set_feature(mpam_feat_mbw_min, &fake_cfg);
	mpam_extend_config(&fake_class, &fake_cfg);
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_max, &fake_cfg));
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_min, &fake_cfg));
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_max, 0xfeef);
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_min, 0xfeef);

	/* When a min is missing, it is generated */
	fake_class.props.bwa_wd = 16;
	fake_cfg.mbw_max = 0xfeef;
	fake_cfg.mbw_min = 0;
	fake_cfg.features = 0;
	mpam_set_feature(mpam_feat_mbw_max, &fake_cfg);
	mpam_extend_config(&fake_class, &fake_cfg);
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_max, &fake_cfg));
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_min, &fake_cfg));
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_max, 0xfeef);
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_min, 0xf224);

	fake_class.props.bwa_wd = 8;
	fake_cfg.mbw_max = 0xfeef;
	fake_cfg.mbw_min = 0;
	fake_cfg.features = 0;
	mpam_set_feature(mpam_feat_mbw_max, &fake_cfg);
	mpam_extend_config(&fake_class, &fake_cfg);
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_max, &fake_cfg));
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_min, &fake_cfg));
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_max, 0xfeef);
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_min, 0xf224);

	/* 5% below the minimum granule, is still the minimum granule */
	fake_class.props.bwa_wd = 12;
	fake_cfg.mbw_max = 0xf;
	fake_cfg.mbw_min = 0;
	fake_cfg.features = 0;
	mpam_set_feature(mpam_feat_mbw_max, &fake_cfg);
	mpam_extend_config(&fake_class, &fake_cfg);
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_max, &fake_cfg));
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_min, &fake_cfg));
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_max, 0xf);
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_min, 0xf);

	fake_class.props.bwa_wd = 16;
	fake_cfg.mbw_max = 0x4;
	fake_cfg.mbw_min = 0;
	fake_cfg.features = 0;
	mpam_set_feature(mpam_feat_mbw_max, &fake_cfg);
	mpam_extend_config(&fake_class, &fake_cfg);
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_max, &fake_cfg));
	KUNIT_EXPECT_TRUE(test, mpam_has_feature(mpam_feat_mbw_min, &fake_cfg));
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_max, 0x4);
	KUNIT_EXPECT_EQ(test, fake_cfg.mbw_min, 0x0);
}

static void test_mpam_reset_msc_bitmap(struct kunit *test)
{
	char *buf = kunit_kzalloc(test, SZ_16K, GFP_KERNEL);
	struct mpam_msc fake_msc = {0};
	u32 *test_result;

	if (!buf)
		return;

	fake_msc.mapped_hwpage = buf;
	fake_msc.mapped_hwpage_sz = SZ_16K;
	cpumask_copy(&fake_msc.accessibility, cpu_possible_mask);

	mutex_init(&fake_msc.part_sel_lock);
	mutex_lock(&fake_msc.part_sel_lock);

	test_result = (u32 *)(buf + MPAMCFG_CPBM);

	mpam_reset_msc_bitmap(&fake_msc, MPAMCFG_CPBM, 0);
	KUNIT_EXPECT_EQ(test, test_result[0], 0);
	KUNIT_EXPECT_EQ(test, test_result[1], 0);
	test_result[0] = 0;
	test_result[1] = 0;

	mpam_reset_msc_bitmap(&fake_msc, MPAMCFG_CPBM, 1);
	KUNIT_EXPECT_EQ(test, test_result[0], 1);
	KUNIT_EXPECT_EQ(test, test_result[1], 0);
	test_result[0] = 0;
	test_result[1] = 0;

	mpam_reset_msc_bitmap(&fake_msc, MPAMCFG_CPBM, 16);
	KUNIT_EXPECT_EQ(test, test_result[0], 0xffff);
	KUNIT_EXPECT_EQ(test, test_result[1], 0);
	test_result[0] = 0;
	test_result[1] = 0;

	mpam_reset_msc_bitmap(&fake_msc, MPAMCFG_CPBM, 32);
	KUNIT_EXPECT_EQ(test, test_result[0], 0xffffffff);
	KUNIT_EXPECT_EQ(test, test_result[1], 0);
	test_result[0] = 0;
	test_result[1] = 0;

	mpam_reset_msc_bitmap(&fake_msc, MPAMCFG_CPBM, 33);
	KUNIT_EXPECT_EQ(test, test_result[0], 0xffffffff);
	KUNIT_EXPECT_EQ(test, test_result[1], 1);
	test_result[0] = 0;
	test_result[1] = 0;

	mutex_unlock(&fake_msc.part_sel_lock);
}

static struct kunit_case mpam_devices_test_cases[] = {
	KUNIT_CASE(test_mpam_reset_msc_bitmap),
	KUNIT_CASE(test_mpam_extend_config),
	{}
};

static struct kunit_suite mpam_devices_test_suite = {
	.name = "mpam_devices_test_suite",
	.test_cases = mpam_devices_test_cases,
};

kunit_test_suites(&mpam_devices_test_suite);

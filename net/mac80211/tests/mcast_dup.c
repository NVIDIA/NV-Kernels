// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>

#include "../ieee80211_i.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static const struct ethhdr mcast_frame = {
	.h_source = { 0x02, 0, 0, 0, 0, 1 },
	.h_dest = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
};

static int mcast_dup_init(struct kunit *test)
{
	test->priv = kunit_kzalloc(test, sizeof(struct ieee80211_mcast_dup_cache),
				   GFP_KERNEL);
	return test->priv ? 0 : -ENOMEM;
}

static void mcast_dup_links(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;

	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, 1));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							  100, 1, 2));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							  100, 2, 3));
}

static void mcast_dup_unordered(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	static const u16 seqs[] = { 837, 1373, 623, 627, 630, 4095, 0, 1 };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(seqs); i++)
		KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache,
								   &mcast_frame, seqs[i], 0, 1));
	for (i = 0; i < ARRAY_SIZE(seqs); i++)
		KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache,
								  &mcast_frame, seqs[i], 1, 2));
}

static void mcast_dup_addresses(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	struct ethhdr other = mcast_frame;

	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &other,
							   100, 0, 1));
	other.h_source[5]++;
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &other,
							   100, 1, 2));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &other,
							  100, 2, 3));
	other.h_dest[5]--;
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &other,
							   100, 0, 4));
}

static void mcast_dup_reuse(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 expiry = IEEE80211_MCAST_DUP_TIMEOUT + 1;

	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, 1));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							  100, 1, 2));
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, 3));
	/* The old and new generations can no longer be distinguished. */
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 2, 4));
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 1, expiry - 1));
	/* Reuse did not keep the original entry alive. */
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, expiry));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							  100, 1, expiry + 1));
}

static void mcast_dup_expiry(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 expiry = IEEE80211_MCAST_DUP_TIMEOUT + 1;

	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, 1));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							  100, 1, expiry - 1));
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 2, expiry));
}

static void mcast_dup_capacity(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u16 sn;

	for (sn = 0; sn < IEEE80211_SN_MODULO; sn++)
		KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache,
								   &mcast_frame, sn, 0, 1));
	for (sn = 0; sn < IEEE80211_SN_MODULO; sn++)
		KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache,
								  &mcast_frame, sn, 1, 2));
}

static void mcast_dup_time_wrap(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 now = U32_MAX;

	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, now));
	/* A timestamp epoch change fails open, including for recent entries. */
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 1, now + 1));
	KUNIT_EXPECT_TRUE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							  100, 2, now + 2));
	/* The same low timestamp after a full wrap must not match stale data. */
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, 0, now + 1 + BIT_ULL(32)));
}

static void mcast_dup_missing_state(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;

	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(NULL, &mcast_frame,
							   100, 0, 1));
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, -1, 1));
	KUNIT_EXPECT_FALSE(test, ieee80211_mcast_dup_check(cache, &mcast_frame,
							   100, IEEE80211_MLD_MAX_NUM_LINKS, 1));
}

static struct kunit_case mcast_dup_cases[] = {
	KUNIT_CASE(mcast_dup_links),
	KUNIT_CASE(mcast_dup_unordered),
	KUNIT_CASE(mcast_dup_addresses),
	KUNIT_CASE(mcast_dup_reuse),
	KUNIT_CASE(mcast_dup_expiry),
	KUNIT_CASE(mcast_dup_capacity),
	KUNIT_CASE(mcast_dup_time_wrap),
	KUNIT_CASE(mcast_dup_missing_state),
	{}
};

static struct kunit_suite mcast_dup_suite = {
	.name = "mac80211_mcast_dup",
	.init = mcast_dup_init,
	.test_cases = mcast_dup_cases,
};

kunit_test_suite(mcast_dup_suite);

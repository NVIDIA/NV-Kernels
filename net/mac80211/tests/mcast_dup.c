// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>

#include "../ieee80211_i.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static const struct ethhdr mcast_frame = {
	.h_source = { 0x02, 0, 0, 0, 0, 1 },
	.h_dest = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
};

static bool check(struct ieee80211_mcast_dup_cache *cache,
		  const struct ethhdr *ehdr, u16 sn, int link_id, u64 now)
{
	return ieee80211_mcast_dup_check(cache, ehdr, sn, false, link_id, now,
					 IEEE80211_MCAST_DUP_TIMEOUT);
}

static bool check_full(struct ieee80211_mcast_dup_cache *cache, u16 sn,
		       bool retry, int link_id, u64 now, u32 timeout)
{
	return ieee80211_mcast_dup_check(cache, &mcast_frame, sn, retry,
					 link_id, now, timeout);
}

static int mcast_dup_init(struct kunit *test)
{
	test->priv = kunit_kzalloc(test, sizeof(struct ieee80211_mcast_dup_cache),
				   GFP_KERNEL);
	return test->priv ? 0 : -ENOMEM;
}

static void mcast_dup_links(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, 1));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 1, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 2, 3));
}

static void mcast_dup_unordered(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	static const u16 seqs[] = { 837, 1373, 623, 627, 630, 4095, 0, 1 };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(seqs); i++)
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, seqs[i], 0, 1));
	for (i = 0; i < ARRAY_SIZE(seqs); i++)
		KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, seqs[i], 1, 2));
}

static void mcast_dup_addresses(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	struct ethhdr other = mcast_frame;

	KUNIT_EXPECT_FALSE(test, check(cache, &other, 100, 0, 1));
	other.h_source[5]++;
	KUNIT_EXPECT_FALSE(test, check(cache, &other, 100, 1, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &other, 100, 2, 3));
	other.h_dest[5]--;
	KUNIT_EXPECT_FALSE(test, check(cache, &other, 100, 0, 4));
}

/* Copies of different address pairs with the same SN may interleave. */
static void mcast_dup_interleaved(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	struct ethhdr other = mcast_frame;

	other.h_source[5]++;
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, 1));
	KUNIT_EXPECT_FALSE(test, check(cache, &other, 100, 0, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 1, 3));
	KUNIT_EXPECT_TRUE(test, check(cache, &other, 100, 1, 4));
}

static void mcast_dup_reuse(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 expiry = IEEE80211_MCAST_DUP_TIMEOUT + 1;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, 1));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 1, 2));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, 3));
	/* The old and new generations can no longer be distinguished. */
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 2, 4));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 1, expiry - 1));
	/* Reuse did not keep the original entry alive. */
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, expiry));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 1, expiry + 1));
}

/* A same-link retransmission is a copy, unlike same-link reuse. */
static void mcast_dup_retry(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u32 timeout = IEEE80211_MCAST_DUP_TIMEOUT;

	KUNIT_EXPECT_FALSE(test, check_full(cache, 100, false, 0, 1, timeout));
	KUNIT_EXPECT_TRUE(test, check_full(cache, 100, true, 0, 2, timeout));
	KUNIT_EXPECT_TRUE(test, check_full(cache, 100, true, 1, 3, timeout));
	KUNIT_EXPECT_TRUE(test, check_full(cache, 100, false, 2, 4, timeout));
	KUNIT_EXPECT_FALSE(test, check_full(cache, 100, false, 0, 5, timeout));
	/* Once reuse was seen, even a retransmission fails open. */
	KUNIT_EXPECT_FALSE(test, check_full(cache, 100, true, 1, 6, timeout));
}

static void mcast_dup_expiry(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 expiry = IEEE80211_MCAST_DUP_TIMEOUT + 1;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, 1));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 1, expiry - 1));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 2, expiry));
}

/* Links with long DTIM intervals can extend the lifetime. */
static void mcast_dup_long_timeout(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u32 timeout = IEEE80211_MCAST_DUP_TIMEOUT + HZ;

	KUNIT_EXPECT_FALSE(test, check_full(cache, 100, false, 0, 1, timeout));
	KUNIT_EXPECT_TRUE(test, check_full(cache, 100, false, 1, timeout,
					   timeout));
	KUNIT_EXPECT_FALSE(test, check_full(cache, 100, false, 2, timeout + 1,
					    timeout));
}

static void mcast_dup_capacity(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u16 window = IEEE80211_MCAST_DUP_BUCKETS * IEEE80211_MCAST_DUP_WAYS;
	u16 sn;

	for (sn = 0; sn < window; sn++)
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, sn, 0, 1));
	for (sn = 0; sn < window; sn++)
		KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, sn, 1, 2));

	/* A new position replaces the one furthest behind it. */
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, window, 0, 3));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 2, 4));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 1, 2, 4));
}

/* A full bucket replaces the entry furthest behind the newest SN. */
static void mcast_dup_evict(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	static const u16 seqs[] = { 512, 0, 1024, 1536, 2048 };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(seqs); i++)
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, seqs[i], 0, 1));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 512, 1, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 1024, 1, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 1536, 1, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 2048, 1, 2));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 1, 2));
}

/* A late copy is still matched after the newest SN has wrapped. */
static void mcast_dup_behind_wrap(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u16 sn;

	for (sn = 4000; sn != 11; sn = (sn + 1) % IEEE80211_SN_MODULO)
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, sn, 0, 1));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 4000, 1, 2));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 10, 1, 2));
}

/*
 * SN 0 is received only on link 0. A full SN cycle later, within the
 * timeout, a new frame with SN 0 is received on link 1.
 */
static void mcast_dup_sn_wrap(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 cycle = IEEE80211_MCAST_DUP_TIMEOUT * 2 / 5;
	u64 now;
	u16 sn;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 0, 1));
	for (sn = 1; sn < IEEE80211_SN_MODULO; sn++) {
		now = 1 + sn * cycle / IEEE80211_SN_MODULO;
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, sn, 0, now));
	}
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 1, 1 + cycle));
}

/* As above, with the cycle made up of other address pairs. */
static void mcast_dup_sn_wrap_other_streams(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 cycle = IEEE80211_MCAST_DUP_TIMEOUT * 2 / 5;
	struct ethhdr other = mcast_frame;
	u64 now;
	u16 sn;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 0, 1));
	for (sn = 1; sn < IEEE80211_SN_MODULO; sn++) {
		now = 1 + sn * cycle / IEEE80211_SN_MODULO;
		other.h_source[5] = sn % 7 + 2;
		KUNIT_EXPECT_FALSE(test, check(cache, &other, sn, 0, now));
	}
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 1, 1 + cycle));
}

/* As above, when only about one in eight frames of the cycle is received. */
static void mcast_dup_sn_wrap_sparse(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 cycle = IEEE80211_MCAST_DUP_TIMEOUT * 2 / 5;
	u32 lcg = 12345;
	u64 now;
	u16 sn;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 0, 1));
	for (sn = 1; sn < IEEE80211_SN_MODULO; sn++) {
		lcg = lcg * 1103515245 + 12345;
		if ((lcg >> 16) & 7)
			continue;
		now = 1 + sn * cycle / IEEE80211_SN_MODULO;
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, sn, 0, now));
	}
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 0, 1, 1 + cycle));
}

/* Missing more than half the SN space must not drop first copies. */
static void mcast_dup_gap(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u16 sn;

	for (sn = 0; sn < 100; sn++) {
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, sn, 0, 1));
		KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, sn, 1, 1));
	}
	/* SNs 100-2999 are missed, then the counter wraps to known SNs. */
	for (sn = 3000; sn != 100; sn = (sn + 1) % IEEE80211_SN_MODULO)
		KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, sn, 0, 2));
}

static void mcast_dup_time_wrap(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;
	u64 now = U32_MAX;

	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0, now));
	/* A timestamp epoch change fails open, including for recent entries. */
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 1, now + 1));
	KUNIT_EXPECT_TRUE(test, check(cache, &mcast_frame, 100, 2, now + 2));
	/* The same low timestamp after a full wrap must not match stale data. */
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, 0,
				       now + 1 + BIT_ULL(32)));
}

static void mcast_dup_missing_state(struct kunit *test)
{
	struct ieee80211_mcast_dup_cache *cache = test->priv;

	KUNIT_EXPECT_FALSE(test, check(NULL, &mcast_frame, 100, 0, 1));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100, -1, 1));
	KUNIT_EXPECT_FALSE(test, check(cache, &mcast_frame, 100,
				       IEEE80211_MLD_MAX_NUM_LINKS, 1));
}

static struct kunit_case mcast_dup_cases[] = {
	KUNIT_CASE(mcast_dup_links),
	KUNIT_CASE(mcast_dup_unordered),
	KUNIT_CASE(mcast_dup_addresses),
	KUNIT_CASE(mcast_dup_interleaved),
	KUNIT_CASE(mcast_dup_reuse),
	KUNIT_CASE(mcast_dup_retry),
	KUNIT_CASE(mcast_dup_expiry),
	KUNIT_CASE(mcast_dup_long_timeout),
	KUNIT_CASE(mcast_dup_capacity),
	KUNIT_CASE(mcast_dup_evict),
	KUNIT_CASE(mcast_dup_behind_wrap),
	KUNIT_CASE(mcast_dup_sn_wrap),
	KUNIT_CASE(mcast_dup_sn_wrap_other_streams),
	KUNIT_CASE(mcast_dup_sn_wrap_sparse),
	KUNIT_CASE(mcast_dup_gap),
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

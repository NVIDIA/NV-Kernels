/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MAC80211_MCAST_H
#define __MAC80211_MCAST_H

#include <linux/ieee80211.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>

/*
 * Minimum lifetime of an entry. Links with long DTIM intervals extend it,
 * because an AP may hold group frames until each link's DTIM beacon.
 */
#define IEEE80211_MCAST_DUP_TIMEOUT HZ
#define IEEE80211_MCAST_DUP_TIMEOUT_MAX (4 * HZ)

/*
 * Entries are indexed by position, so 512 buckets of 4 entries cover the
 * last 2048 positions: the same half of the SN space that a high-water mark
 * can order. A full bucket replaces its oldest entry.
 */
#define IEEE80211_MCAST_DUP_BUCKETS 512
#define IEEE80211_MCAST_DUP_WAYS 4

struct ieee80211_mcast_dup_entry {
	u32 seen;
	u32 pos;
	u16 links;
	u8 sa[ETH_ALEN] __aligned(2);
	u8 da[ETH_ALEN] __aligned(2);
	bool ambiguous;
};

struct ieee80211_mcast_dup_cache {
	struct rcu_head rcu_head;
	u32 epoch;
	/* newest SN seen, extended to 32 bits so wraps stay distinct */
	u32 head;
	bool started;
	struct ieee80211_mcast_dup_entry
		entries[IEEE80211_MCAST_DUP_BUCKETS][IEEE80211_MCAST_DUP_WAYS];
};

#endif /* __MAC80211_MCAST_H */

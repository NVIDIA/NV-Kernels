/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MAC80211_MCAST_H
#define __MAC80211_MCAST_H

#include <linux/ieee80211.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>

#define IEEE80211_MCAST_DUP_TIMEOUT HZ

struct ieee80211_mcast_dup_entry {
	u32 seen;
	u16 links;
	u8 sa[ETH_ALEN] __aligned(2);
	u8 da[ETH_ALEN] __aligned(2);
	bool ambiguous;
};

struct ieee80211_mcast_dup_cache {
	struct rcu_head rcu_head;
	u32 epoch;
	struct ieee80211_mcast_dup_entry entries[IEEE80211_SN_MODULO];
};

#endif /* __MAC80211_MCAST_H */

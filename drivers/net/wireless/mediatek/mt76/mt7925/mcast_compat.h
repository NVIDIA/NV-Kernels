/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/* Duplicate checking for group frames from selected AP MLDs. */
#ifndef __MT7925_MCAST_COMPAT_H
#define __MT7925_MCAST_COMPAT_H

#define MT7925_MCAST_COMPAT_ENTRIES 256
#define MT7925_MCAST_COMPAT_MAX_PAYLOAD 2304
#define MT7925_MCAST_COMPAT_HOLD (2 * HZ)

struct mt7925_mcast_compat_frame {
	const void *dev;
	u8 local_mld[ETH_ALEN], ap_mld[ETH_ALEN];
	u8 source[ETH_ALEN], destination[ETH_ALEN];
	u16 seq_ctrl, len;
	const u8 *payload;
};

struct mt7925_mcast_compat_entry {
	const void *dev;
	u8 local_mld[ETH_ALEN], ap_mld[ETH_ALEN];
	u8 source[ETH_ALEN], destination[ETH_ALEN];
	u16 seq_ctrl, len;
	unsigned long seen;
	bool valid;
	u8 payload[MT7925_MCAST_COMPAT_MAX_PAYLOAD];
};

/* Caller holds the lock. Association and group-key changes delimit epochs. */
static void
mt7925_mcast_compat_clear(struct mt7925_mcast_compat_entry *cache,
			const void *dev, const u8 *local_mld)
{
	unsigned int i;

	for (i = 0; i < MT7925_MCAST_COMPAT_ENTRIES; i++)
		if (cache[i].valid && cache[i].dev == dev &&
		    ether_addr_equal(cache[i].local_mld, local_mld))
			cache[i].valid = false;
}

/* Caller holds the lock. A reused sequence with different contents is fresh.
 * Exclude link TA so identical MLD copies can be checked across active links.
 * Finite retention/capacity can admit late/displaced duplicate copies; this
 * is a scoped compatibility quirk, not cryptographic replay protection.
 */
static bool
mt7925_mcast_compat_duplicate(struct mt7925_mcast_compat_entry *cache,
			    unsigned int *next,
			    const struct mt7925_mcast_compat_frame *frame,
			    unsigned long now)
{
	struct mt7925_mcast_compat_entry *entry;
	unsigned int i;

	for (i = 0; i < MT7925_MCAST_COMPAT_ENTRIES; i++) {
		entry = &cache[i];
		if (!entry->valid ||
		    time_after_eq(now, entry->seen + MT7925_MCAST_COMPAT_HOLD) ||
		    entry->dev != frame->dev || entry->seq_ctrl != frame->seq_ctrl ||
		    entry->len != frame->len ||
		    !ether_addr_equal(entry->local_mld, frame->local_mld) ||
		    !ether_addr_equal(entry->ap_mld, frame->ap_mld) ||
		    !ether_addr_equal(entry->source, frame->source) ||
		    !ether_addr_equal(entry->destination, frame->destination))
			continue;
		if (!memcmp(entry->payload, frame->payload, frame->len))
			return true;
	}
	entry = &cache[*next];
	*next = (*next + 1) % MT7925_MCAST_COMPAT_ENTRIES;
	entry->dev = frame->dev;
	ether_addr_copy(entry->local_mld, frame->local_mld);
	ether_addr_copy(entry->ap_mld, frame->ap_mld);
	ether_addr_copy(entry->source, frame->source);
	ether_addr_copy(entry->destination, frame->destination);
	entry->seq_ctrl = frame->seq_ctrl;
	entry->len = frame->len;
	entry->seen = now;
	entry->valid = true;
	memcpy(entry->payload, frame->payload, frame->len);
	return false;
}

/* Keep malformed, fragmented, translated, error/monitor, plaintext and QoS
 * frames on their original paths. Association/AP allowlisting is separate.
 */
static bool
mt7925_mcast_compat_candidate(struct sk_buff *skb, u32 flags,
			      unsigned int *hlen)
{
	struct ieee80211_hdr *hdr;

	if (skb->len < 32 || skb->len != skb_headlen(skb) ||
	    !(flags & RX_FLAG_DECRYPTED) || !(flags & RX_FLAG_IV_STRIPPED) ||
	    (flags & (RX_FLAG_ONLY_MONITOR | RX_FLAG_FAILED_FCS_CRC |
		      RX_FLAG_MMIC_ERROR | RX_FLAG_8023 | RX_FLAG_DUP_VALIDATED)))
		return false;
	hdr = (struct ieee80211_hdr *)skb->data;
	if (!ieee80211_is_data_present(hdr->frame_control) ||
	    ieee80211_is_data_qos(hdr->frame_control) ||
	    !ieee80211_has_fromds(hdr->frame_control) ||
	    ieee80211_has_tods(hdr->frame_control) ||
	    !ieee80211_has_protected(hdr->frame_control) ||
	    ieee80211_has_morefrags(hdr->frame_control) ||
	    (le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG) ||
	    !is_multicast_ether_addr(hdr->addr1) ||
	    !is_valid_ether_addr(hdr->addr3))
		return false;
	*hlen = ieee80211_hdrlen(hdr->frame_control);
	if (skb->len < *hlen + 8 ||
	    skb->len - *hlen > MT7925_MCAST_COMPAT_MAX_PAYLOAD)
		return false;
	return skb->data[*hlen] == 0xaa && skb->data[*hlen + 1] == 0xaa &&
	       skb->data[*hlen + 2] == 3;
}

#endif

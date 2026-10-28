/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/* Duplicate checking for source-selected link-local LLDP frames. */
#ifndef __MT7925_LLDP_RX_H
#define __MT7925_LLDP_RX_H

#define MT7925_LLDP_CACHE_SIZE 8
#define MT7925_LLDP_PAYLOAD_MAX 2048

struct mt7925_lldp_frame {
	const void *dev;
	u8 local_mld[ETH_ALEN];
	u8 ap_mld[ETH_ALEN];
	u8 source[ETH_ALEN];
	u16 seq_ctrl;
	u16 len;
	const u8 *payload;
};

struct mt7925_lldp_entry {
	const void *dev;
	u8 local_mld[ETH_ALEN];
	u8 ap_mld[ETH_ALEN];
	u8 source[ETH_ALEN];
	u16 seq_ctrl;
	u16 len;
	unsigned long seen;
	bool valid;
	u8 payload[MT7925_LLDP_PAYLOAD_MAX];
};

/* Caller holds the cache lock. A different payload with a reused sequence
 * number is not a duplicate. Do not refresh timestamps for duplicate copies.
 * The cache is only for the configured source's link-local control frames.
 */
static bool
mt7925_lldp_cache_duplicate(struct mt7925_lldp_entry *cache, unsigned int *next,
			    const struct mt7925_lldp_frame *frame,
			    unsigned long now)
{
	struct mt7925_lldp_entry *entry;
	unsigned int i;

	for (i = 0; i < MT7925_LLDP_CACHE_SIZE; i++) {
		entry = &cache[i];
		if (!entry->valid || time_after_eq(now, entry->seen + HZ) ||
		    entry->dev != frame->dev ||
		    entry->seq_ctrl != frame->seq_ctrl || entry->len != frame->len ||
		    !ether_addr_equal(entry->local_mld, frame->local_mld) ||
		    !ether_addr_equal(entry->ap_mld, frame->ap_mld) ||
		    !ether_addr_equal(entry->source, frame->source))
			continue;
		if (!memcmp(entry->payload, frame->payload, frame->len))
			return true;
	}

	entry = &cache[*next];
	*next = (*next + 1) % MT7925_LLDP_CACHE_SIZE;
	entry->dev = frame->dev;
	ether_addr_copy(entry->local_mld, frame->local_mld);
	ether_addr_copy(entry->ap_mld, frame->ap_mld);
	ether_addr_copy(entry->source, frame->source);
	entry->seq_ctrl = frame->seq_ctrl;
	entry->len = frame->len;
	entry->seen = now;
	memcpy(entry->payload, frame->payload, frame->len);
	entry->valid = true;
	return false;
}

/* Select complete, hardware-decrypted LLDP frames to the link-local destination
 * from the configured bridge source.
 */
static bool
mt7925_lldp_candidate(struct sk_buff *skb, u32 flags, const u8 *source,
		      unsigned int *hlen)
{
	static const u8 destination[ETH_ALEN] = { 1, 0x80, 0xc2, 0, 0, 0x0e };
	struct ieee80211_hdr *hdr;

	if (skb->len < 24 || skb->len != skb_headlen(skb) ||
	    !(flags & RX_FLAG_DECRYPTED) || !(flags & RX_FLAG_IV_STRIPPED) ||
	    (flags & (RX_FLAG_ONLY_MONITOR | RX_FLAG_FAILED_FCS_CRC |
		      RX_FLAG_FAILED_PLCP_CRC | RX_FLAG_MMIC_ERROR | RX_FLAG_8023)))
		return false;

	hdr = (struct ieee80211_hdr *)skb->data;
	if (!ieee80211_is_data_present(hdr->frame_control) ||
	    !ieee80211_has_fromds(hdr->frame_control) ||
	    ieee80211_has_tods(hdr->frame_control) ||
	    !ieee80211_has_protected(hdr->frame_control) ||
	    ieee80211_has_morefrags(hdr->frame_control) ||
	    (le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG) ||
	    !ether_addr_equal(hdr->addr1, destination) ||
	    !ether_addr_equal(hdr->addr3, source))
		return false;

	*hlen = ieee80211_hdrlen(hdr->frame_control);
	if (skb->len < *hlen + 8 || skb->len - *hlen > MT7925_LLDP_PAYLOAD_MAX)
		return false;
	/* Require RFC 1042 encapsulation and the LLDP EtherType. */
	if (memcmp(skb->data + *hlen, rfc1042_header, sizeof(rfc1042_header)) ||
	    get_unaligned_be16(skb->data + *hlen + sizeof(rfc1042_header)) !=
	    ETH_P_LLDP)
		return false;
	if (ieee80211_is_data_qos(hdr->frame_control) &&
	    (*ieee80211_get_qos_ctl(hdr) & IEEE80211_QOS_CTL_A_MSDU_PRESENT))
		return false;
	return true;
}

#endif

/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef ALX_HW_H_
#define ALX_HW_H_

/* specific error info */
#define ALX_ERR_SUCCESS          0x0000
#define ALX_ERR_ALOAD            0x0001
#define ALX_ERR_RSTMAC           0x0002
#define ALX_ERR_PARM             0x0003
#define ALX_ERR_MIIBUSY          0x0004
#define ALX_LINK_TIMEOUT	 0x0008

/* Transmit Packet Descriptor, contains 4 32-bit words.
 *
 *   31               16               0
 *   +----------------+----------------+
 *   |    vlan-tag    |   buf length   |
 *   +----------------+----------------+
 *   |              Word 1             |
 *   +----------------+----------------+
 *   |      Word 2: buf addr lo        |
 *   +----------------+----------------+
 *   |      Word 3: buf addr hi        |
 *   +----------------+----------------+
 *
 * Word 2 and 3 combine to form a 64-bit buffer address
 *
 * Word 1 has three forms, depending on the state of bit 8/12/13:
 * if bit8 =='1', the definition is just for custom checksum offload.
 * if bit8 == '0' && bit12 == '1' && bit13 == '1', the *FIRST* descriptor
 *     for the skb is special for LSO V2, Word 2 become total skb length ,
 *     Word 3 is meaningless.
 * other condition, the definition is for general skb or ip/tcp/udp
 *     checksum or LSO(TSO) offload.
 *
 * Here is the depiction:
 *
 *   0-+                                  0-+
 *   1 |                                  1 |
 *   2 |                                  2 |
 *   3 |    Payload offset                3 |    L4 header offset
 *   4 |        (7:0)                     4 |        (7:0)
 *   5 |                                  5 |
 *   6 |                                  6 |
 *   7-+                                  7-+
 *   8      Custom csum enable = 1        8      Custom csum enable = 0
 *   9      General IPv4 checksum         9      General IPv4 checksum
 *   10     General TCP checksum          10     General TCP checksum
 *   11     General UDP checksum          11     General UDP checksum
 *   12     Large Send Segment enable     12     Large Send Segment enable
 *   13     Large Send Segment type       13     Large Send Segment type
 *   14     VLAN tagged                   14     VLAN tagged
 *   15     Insert VLAN tag               15     Insert VLAN tag
 *   16     IPv4 packet                   16     IPv4 packet
 *   17     Ethernet frame type           17     Ethernet frame type
 *   18-+                                 18-+
 *   19 |                                 19 |
 *   20 |                                 20 |
 *   21 |   Custom csum offset            21 |
 *   22 |       (25:18)                   22 |
 *   23 |                                 23 |   MSS (30:18)
 *   24 |                                 24 |
 *   25-+                                 25 |
 *   26-+                                 26 |
 *   27 |                                 27 |
 *   28 |   Reserved                      28 |
 *   29 |                                 29 |
 *   30-+                                 30-+
 *   31     End of packet                 31     End of packet
 */

struct tpd_desc {
	__le32 word0;
	__le32 word1;
	union {
		__le64 addr;
		struct {
			__le32 pkt_len;
			__le32 resvd;
		} l;
	} adrl;
} __packed;

/* tpd word 0 */
#define TPD_BUFLEN_MASK			0xFFFF
#define TPD_BUFLEN_SHIFT		0
#define TPD_VLTAG_MASK			0xFFFF
#define TPD_VLTAG_SHIFT			16

/* tpd word 1 */
#define TPD_CXSUMSTART_MASK		0x00FF
#define TPD_CXSUMSTART_SHIFT		0
#define TPD_L4HDROFFSET_MASK		0x00FF
#define TPD_L4HDROFFSET_SHIFT		0
#define TPD_CXSUM_EN_MASK		0x0001
#define TPD_CXSUM_EN_SHIFT		8
#define TPD_IP_XSUM_MASK		0x0001
#define TPD_IP_XSUM_SHIFT		9
#define TPD_TCP_XSUM_MASK		0x0001
#define TPD_TCP_XSUM_SHIFT		10
#define TPD_UDP_XSUM_MASK		0x0001
#define TPD_UDP_XSUm_SHIFT		11
#define TPD_LSO_EN_MASK			0x0001
#define TPD_LSO_EN_SHIFT		12
#define TPD_LSO_V2_MASK			0x0001
#define TPD_LSO_V2_SHIFT		13
#define TPD_VLTAGGED_MASK		0x0001
#define TPD_VLTAGGED_SHIFT		14
#define TPD_INS_VLTAG_MASK		0x0001
#define TPD_INS_VLTAG_SHIFT		15
#define TPD_IPV4_MASK			0x0001
#define TPD_IPV4_SHIFT			16
#define TPD_ETHTYPE_MASK		0x0001
#define TPD_ETHTYPE_SHIFT		17
#define TPD_CXSUMOFFSET_MASK		0x00FF
#define TPD_CXSUMOFFSET_SHIFT		18
#define TPD_MSS_MASK			0x1FFF
#define TPD_MSS_SHIFT			18
#define TPD_EOP_MASK			0x0001
#define TPD_EOP_SHIFT			31

#define DESC_GET(_x, _name) ((_x) >> _name##SHIFT & _name##MASK)

/* Receive Free Descriptor */
struct rfd_desc {
	__le64 addr;		/* data buffer address, length is
				 * declared in register --- every
				 * buffer has the same size
				 */
} __packed;

/* Receive Return Descriptor, contains 4 32-bit words.
 *
 *   31               16               0
 *   +----------------+----------------+
 *   |              Word 0             |
 *   +----------------+----------------+
 *   |     Word 1: RSS Hash value      |
 *   +----------------+----------------+
 *   |              Word 2             |
 *   +----------------+----------------+
 *   |              Word 3             |
 *   +----------------+----------------+
 *
 * Word 0 depiction         &            Word 2 depiction:
 *
 *   0--+                                 0--+
 *   1  |                                 1  |
 *   2  |                                 2  |
 *   3  |                                 3  |
 *   4  |                                 4  |
 *   5  |                                 5  |
 *   6  |                                 6  |
 *   7  |    IP payload checksum          7  |     VLAN tag
 *   8  |         (15:0)                  8  |      (15:0)
 *   9  |                                 9  |
 *   10 |                                 10 |
 *   11 |                                 11 |
 *   12 |                                 12 |
 *   13 |                                 13 |
 *   14 |                                 14 |
 *   15-+                                 15-+
 *   16-+                                 16-+
 *   17 |     Number of RFDs              17 |
 *   18 |        (19:16)                  18 |
 *   19-+                                 19 |     Protocol ID
 *   20-+                                 20 |      (23:16)
 *   21 |                                 21 |
 *   22 |                                 22 |
 *   23 |                                 23-+
 *   24 |                                 24 |     Reserved
 *   25 |     Start index of RFD-ring     25-+
 *   26 |         (31:20)                 26 |     RSS Q-num (27:25)
 *   27 |                                 27-+
 *   28 |                                 28-+
 *   29 |                                 29 |     RSS Hash algorithm
 *   30 |                                 30 |      (31:28)
 *   31-+                                 31-+
 *
 * Word 3 depiction:
 *
 *   0--+
 *   1  |
 *   2  |
 *   3  |
 *   4  |
 *   5  |
 *   6  |
 *   7  |    Packet length (include FCS)
 *   8  |         (13:0)
 *   9  |
 *   10 |
 *   11 |
 *   12 |
 *   13-+
 *   14      L4 Header checksum error
 *   15      IPv4 checksum error
 *   16      VLAN tagged
 *   17-+
 *   18 |    Protocol ID (19:17)
 *   19-+
 *   20      Receive error summary
 *   21      FCS(CRC) error
 *   22      Frame alignment error
 *   23      Truncated packet
 *   24      Runt packet
 *   25      Incomplete packet due to insufficient rx-desc
 *   26      Broadcast packet
 *   27      Multicast packet
 *   28      Ethernet type (EII or 802.3)
 *   29      FIFO overflow
 *   30      Length error (for 802.3, length field mismatch with actual len)
 *   31      Updated, indicate to driver that this RRD is refreshed.
 */

struct rrd_desc {
	__le32 word0;
	__le32 rss_hash;
	__le32 word2;
	__le32 word3;
} __packed;

/* rrd word 0 */
#define RRD_XSUM_MASK		0xFFFF
#define RRD_XSUM_SHIFT		0
#define RRD_NOR_MASK		0x000F
#define RRD_NOR_SHIFT		16
#define RRD_SI_MASK		0x0FFF
#define RRD_SI_SHIFT		20

/* rrd word 2 */
#define RRD_VLTAG_MASK		0xFFFF
#define RRD_VLTAG_SHIFT		0
#define RRD_PID_MASK		0x00FF
#define RRD_PID_SHIFT		16
/* non-ip packet */
#define RRD_PID_NONIP		0
/* ipv4(only) */
#define RRD_PID_IPV4		1
/* tcp/ipv6 */
#define RRD_PID_IPV6TCP		2
/* tcp/ipv4 */
#define RRD_PID_IPV4TCP		3
/* udp/ipv6 */
#define RRD_PID_IPV6UDP		4
/* udp/ipv4 */
#define RRD_PID_IPV4UDP		5
/* ipv6(only) */
#define RRD_PID_IPV6		6
/* LLDP packet */
#define RRD_PID_LLDP		7
/* 1588 packet */
#define RRD_PID_1588		8
#define RRD_RSSQ_MASK		0x0007
#define RRD_RSSQ_SHIFT		25
#define RRD_RSSALG_MASK		0x000F
#define RRD_RSSALG_SHIFT	28
#define RRD_RSSALG_TCPV6	0x1
#define RRD_RSSALG_IPV6		0x2
#define RRD_RSSALG_TCPV4	0x4
#define RRD_RSSALG_IPV4		0x8

/* rrd word 3 */
#define RRD_PKTLEN_MASK		0x3FFF
#define RRD_PKTLEN_SHIFT	0
#define RRD_ERR_L4_MASK		0x0001
#define RRD_ERR_L4_SHIFT	14
#define RRD_ERR_IPV4_MASK	0x0001
#define RRD_ERR_IPV4_SHIFT	15
#define RRD_VLTAGGED_MASK	0x0001
#define RRD_VLTAGGED_SHIFT	16
#define RRD_OLD_PID_MASK	0x0007
#define RRD_OLD_PID_SHIFT	17
#define RRD_ERR_RES_MASK	0x0001
#define RRD_ERR_RES_SHIFT	20
#define RRD_ERR_FCS_MASK	0x0001
#define RRD_ERR_FCS_SHIFT	21
#define RRD_ERR_FAE_MASK	0x0001
#define RRD_ERR_FAE_SHIFT	22
#define RRD_ERR_TRUNC_MASK	0x0001
#define RRD_ERR_TRUNC_SHIFT	23
#define RRD_ERR_RUNT_MASK	0x0001
#define RRD_ERR_RUNT_SHIFT	24
#define RRD_ERR_ICMP_MASK	0x0001
#define RRD_ERR_ICMP_SHIFT	25
#define RRD_BCAST_MASK		0x0001
#define RRD_BCAST_SHIFT		26
#define RRD_MCAST_MASK		0x0001
#define RRD_MCAST_SHIFT		27
#define RRD_ETHTYPE_MASK	0x0001
#define RRD_ETHTYPE_SHIFT	28
#define RRD_ERR_FIFOV_MASK	0x0001
#define RRD_ERR_FIFOV_SHIFT	29
#define RRD_ERR_LEN_MASK	0x0001
#define RRD_ERR_LEN_SHIFT	30
#define RRD_UPDATED_MASK	0x0001
#define RRD_UPDATED_SHIFT	31


/* Statistics counters collected by the MAC */
struct alx_hw_stats {
	/* rx */
	unsigned long rx_ok;
	unsigned long rx_bcast;
	unsigned long rx_mcast;
	unsigned long rx_pause;
	unsigned long rx_ctrl;
	unsigned long rx_fcs_err;
	unsigned long rx_len_err;
	unsigned long rx_byte_cnt;
	unsigned long rx_runt;
	unsigned long rx_frag;
	unsigned long rx_sz_64B;
	unsigned long rx_sz_127B;
	unsigned long rx_sz_255B;
	unsigned long rx_sz_511B;
	unsigned long rx_sz_1023B;
	unsigned long rx_sz_1518B;
	unsigned long rx_sz_max;
	unsigned long rx_ov_sz;
	unsigned long rx_ov_rxf;
	unsigned long rx_ov_rrd;
	unsigned long rx_align_err;
	unsigned long rx_bc_byte_cnt;
	unsigned long rx_mc_byte_cnt;
	unsigned long rx_err_addr;

	/* tx */
	unsigned long tx_ok;
	unsigned long tx_bcast;
	unsigned long tx_mcast;
	unsigned long tx_pause;
	unsigned long tx_exc_defer;
	unsigned long tx_ctrl;
	unsigned long tx_defer;
	unsigned long tx_byte_cnt;
	unsigned long tx_sz_64B;
	unsigned long tx_sz_127B;
	unsigned long tx_sz_255B;
	unsigned long tx_sz_511B;
	unsigned long tx_sz_1023B;
	unsigned long tx_sz_1518B;
	unsigned long tx_sz_max;
	unsigned long tx_single_col;
	unsigned long tx_multi_col;
	unsigned long tx_late_col;
	unsigned long tx_abort_col;
	unsigned long tx_underrun;
	unsigned long tx_trd_eop;
	unsigned long tx_len_err;
	unsigned long tx_trunc;
	unsigned long tx_bc_byte_cnt;
	unsigned long tx_mc_byte_cnt;
	unsigned long update;
};

#define SPEED_0			0
#define HALF_DUPLEX		1
#define FULL_DUPLEX		2
#define ALX_MAX_SETUP_LNK_CYCLE	50

#define ALX_SPEED_TO_ETHADV(_speed) (\
(_speed) == SPEED_1000 + FULL_DUPLEX ? ADVERTISED_1000baseT_Full :	\
(_speed) == SPEED_100 + FULL_DUPLEX ? ADVERTISED_100baseT_Full :	\
(_speed) == SPEED_100 + HALF_DUPLEX ? ADVERTISED_10baseT_Half :		\
(_speed) == SPEED_10 + FULL_DUPLEX ? ADVERTISED_10baseT_Full :		\
(_speed) == SPEED_10 + HALF_DUPLEX ? ADVERTISED_10baseT_Half :		\
0)

#define speed_desc(_s) (\
	(_s) == SPEED_1000 + FULL_DUPLEX ? \
	"1 Gbps Full" : \
	(_s) == SPEED_100 + FULL_DUPLEX ? \
	"100 Mbps Full" : \
	(_s) == SPEED_100 + HALF_DUPLEX ? \
	"100 Mbps Half" : \
	(_s) == SPEED_10 + FULL_DUPLEX ? \
	"10 Mbps Full" : \
	(_s) == SPEED_10 + HALF_DUPLEX ? \
	"10 Mbps Half" : \
	"Unknown speed")

/* for FlowControl */
#define ALX_FC_RX		0x01
#define ALX_FC_TX		0x02
#define ALX_FC_ANEG		0x04

/* for sleep control */
#define ALX_SLEEP_WOL_PHY	0x00000001
#define ALX_SLEEP_WOL_MAGIC	0x00000002
#define ALX_SLEEP_CIFS		0x00000004
#define ALX_SLEEP_ACTIVE	(\
	ALX_SLEEP_WOL_PHY | \
	ALX_SLEEP_WOL_MAGIC | \
	ALX_SLEEP_CIFS)

/* for RSS hash type */
#define ALX_RSS_HASH_TYPE_IPV4		0x1
#define ALX_RSS_HASH_TYPE_IPV4_TCP	0x2
#define ALX_RSS_HASH_TYPE_IPV6		0x4
#define ALX_RSS_HASH_TYPE_IPV6_TCP	0x8
#define ALX_RSS_HASH_TYPE_ALL		(\
	ALX_RSS_HASH_TYPE_IPV4 |\
	ALX_RSS_HASH_TYPE_IPV4_TCP |\
	ALX_RSS_HASH_TYPE_IPV6 |\
	ALX_RSS_HASH_TYPE_IPV6_TCP)
#define ALX_DEF_RXBUF_SIZE	1536
#define ALX_MAX_JUMBO_PKT_SIZE	(9*1024)
#define ALX_MAX_TSO_PKT_SIZE	(7*1024)
#define ALX_MAX_FRAME_SIZE	ALX_MAX_JUMBO_PKT_SIZE
#define ALX_MIN_FRAME_SIZE	68
#define ALX_RAW_MTU(_mtu)	(_mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN)

#define ALX_MAX_RX_QUEUES	8
#define ALX_MAX_TX_QUEUES	4
#define ALX_MAX_HANDLED_INTRS	5

#define ALX_ISR_MISC		(\
	ALX_ISR_PCIE_LNKDOWN | \
	ALX_ISR_DMAW | \
	ALX_ISR_DMAR | \
	ALX_ISR_SMB | \
	ALX_ISR_MANU | \
	ALX_ISR_TIMER)

#define ALX_ISR_FATAL	(\
	ALX_ISR_PCIE_LNKDOWN | \
	 ALX_ISR_DMAW | \
	 ALX_ISR_DMAR)

#define ALX_ISR_ALERT	(\
	ALX_ISR_RXF_OV | \
	ALX_ISR_TXF_UR | \
	ALX_ISR_RFD_UR)

#define ALX_ISR_ALL_QUEUES (\
	ALX_ISR_TX_Q0 | \
	ALX_ISR_TX_Q1 | \
	ALX_ISR_TX_Q2 | \
	ALX_ISR_TX_Q3 | \
	ALX_ISR_RX_Q0 | \
	ALX_ISR_RX_Q1 | \
	ALX_ISR_RX_Q2 | \
	ALX_ISR_RX_Q3 | \
	ALX_ISR_RX_Q4 | \
	ALX_ISR_RX_Q5 | \
	ALX_ISR_RX_Q6 | \
	ALX_ISR_RX_Q7)

/* maximum interrupt vectors for msix */
#define ALX_MAX_MSIX_INTRS	16

#define FIELD_GETX(_x, _name)   (((_x) >> (_name##_SHIFT)) & (_name##_MASK))
#define FIELD_SETS(_x, _name, _v)   (\
(_x) =                               \
((_x) & ~((_name##_MASK) << (_name##_SHIFT)))            |\
(((u16)(_v) & (_name##_MASK)) << (_name##_SHIFT)))
#define FIELD_SET32(_x, _name, _v)   (\
(_x) =                               \
((_x) & ~((_name##_MASK) << (_name##_SHIFT)))            |\
(((_v) & (_name##_MASK)) << (_name##_SHIFT)))
#define FIELDX(_name, _v) (((_v) & (_name##_MASK)) << (_name##_SHIFT))

struct alx_hw {
	void *pdev;
	u8 __iomem *hw_addr;

	/* pci regs */
	u16 device_id;
	u16 subdev_id;
	u16 subven_id;
	u8  revision;

	unsigned long capability;

	/* current & permanent mac addr */
	u8 mac_addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];

	u16 mtu;
	u16			imt;
	u8			dma_chnl;
	u8			max_dma_chnl;
	/* tpd threshold to trig INT */
	u32			ith_tpd;
	u32			rx_ctrl;
	u32			mc_hash[2];

	u8			rss_key[40];
	u32			rss_idt[32];
	u16			rss_idt_size;
	u8			rss_hash_type;

	/* weight round robin for multiple-tx-Q */
	u32			wrr[ALX_MAX_TX_QUEUES];
	/* prioirty control */
	u32			wrr_ctrl;

	/* interrupt mask for ALX_IMR */
	u32			imask;
	u32			smb_timer;
	bool			link_up;
	u16			link_speed;
	u8			link_duplex;

	/* auto-neg advertisement or force mode config */
	u32			adv_cfg;
	u8			flowctrl;

	struct alx_hw_stats	hw_stats;
	u32			sleep_ctrl;
	/* sram address for pattern wol */
	u32			ptrn_ofs;
	/* max patterns number */
	u16			max_ptrns;

	spinlock_t		mdio_lock;
	struct mdio_if_info	mdio;
	u16			phy_id[2];

	struct alx_hw_stats	stats;
	/* PHY link patch flag */
	bool			lnk_patch;
	/* PHY hibernation patch flag */
	bool			hib_patch;
	/* FPGA or ASIC */
	bool			is_fpga;
};

#define ALX_DID(_hw)		((_hw)->device_id)
#define ALX_SUB_VID(_hw)	((_hw)->subven_id)
#define ALX_SUB_DID(_hw)	((_hw)->subdev_id)
#define ALX_REVID(_hw)		((_hw)->revision >> ALX_PCI_REVID_SHIFT)
#define ALX_WITH_CR(_hw)	((_hw)->revision & 1)

enum ALX_CAPS {
	ALX_CAP_GIGA = 0,
	ALX_CAP_PTP,
	ALX_CAP_AZ,
	ALX_CAP_L0S,
	ALX_CAP_L1,
	ALX_CAP_SWOI,
	ALX_CAP_RSS,
	ALX_CAP_MSIX,
	/* support Multi-TX-Q */
	ALX_CAP_MTQ,
	/* support Multi-RX-Q */
	ALX_CAP_MRQ,
};
#define ALX_CAP(_hw, _cap) (\
	test_bit(ALX_CAP_##_cap, &(_hw)->capability))
#define ALX_CAP_SET(_hw, _cap) (\
	set_bit(ALX_CAP_##_cap, &(_hw)->capability))
#define ALX_CAP_CLEAR(_hw, _cap) (\
	clear_bit(ALX_CAP_##_cap, &(_hw)->capability))

/* write to 8bit register via pci memory space */
#define ALX_MEM_W8(s, reg, val) (writeb((val), ((s)->hw_addr + reg)))

/* read from 8bit register via pci memory space */
#define ALX_MEM_R8(s, reg, pdat) (\
		*(u8 *)(pdat) = readb((s)->hw_addr + reg))

/* write to 16bit register via pci memory space */
#define ALX_MEM_W16(s, reg, val) (writew((val), ((s)->hw_addr + reg)))

/* read from 16bit register via pci memory space */
#define ALX_MEM_R16(s, reg, pdat) (\
		*(u16 *)(pdat) = readw((s)->hw_addr + reg))

/* write to 32bit register via pci memory space */
#define ALX_MEM_W32(s, reg, val) (writel((val), ((s)->hw_addr + reg)))

/* read from 32bit register via pci memory space */
#define ALX_MEM_R32(s, reg, pdat) (\
		*(u32 *)(pdat) = readl((s)->hw_addr + reg))

/* read from 16bit register via pci config space */
#define ALX_CFG_R16(s, reg, pdat) (\
	pci_read_config_word((s)->pdev, (reg), (pdat)))

/* write to 16bit register via pci config space */
#define ALX_CFG_W16(s, reg, val) (\
	pci_write_config_word((s)->pdev, (reg), (val)))

/* flush regs */
#define ALX_MEM_FLUSH(s) (readl((s)->hw_addr))


int alx_get_perm_macaddr(struct alx_hw *hw, u8 *addr);
void alx_add_mc_addr(struct alx_hw *hw, u8 *addr);
void alx_reset_phy(struct alx_hw *hw, bool hib_en);
void alx_reset_pcie(struct alx_hw *hw);
void alx_enable_aspm(struct alx_hw *hw, bool l0s_en, bool l1_en);
int alx_setup_speed_duplex(struct alx_hw *hw, u32 ethadv, u8 flowctrl);
void alx_post_phy_link(struct alx_hw *hw, u16 speed, bool az_en);
int alx_pre_suspend(struct alx_hw *hw, u16 speed);
int alx_read_phy_reg(struct alx_hw *hw, u16 reg, u16 *phy_data);
int alx_write_phy_reg(struct alx_hw *hw, u16 reg, u16 phy_data);
int alx_read_phy_ext(struct alx_hw *hw, u8 dev, u16 reg, u16 *pdata);
int alx_write_phy_ext(struct alx_hw *hw, u8 dev, u16 reg, u16 data);
int alx_read_phy_dbg(struct alx_hw *hw, u16 reg, u16 *pdata);
int alx_write_phy_dbg(struct alx_hw *hw, u16 reg, u16 data);
int alx_get_phy_link(struct alx_hw *hw, bool *link_up, u16 *speed);
int alx_clear_phy_intr(struct alx_hw *hw);
int alx_config_wol(struct alx_hw *hw);
void alx_cfg_mac_fc(struct alx_hw *hw, u8 fc);
void alx_start_mac(struct alx_hw *hw);
int alx_stop_mac(struct alx_hw *hw);
int alx_reset_mac(struct alx_hw *hw);
void alx_set_macaddr(struct alx_hw *hw, u8 *addr);
bool alx_phy_configed(struct alx_hw *hw);
void alx_configure_basic(struct alx_hw *hw);
void alx_configure_rss(struct alx_hw *hw, bool en);
void alx_mask_msix(struct alx_hw *hw, int index, bool mask);
int alx_select_powersaving_speed(struct alx_hw *hw, u16 *speed);
void __alx_update_hw_stats(struct alx_hw *hw);
void __alx_start_phy_polling(struct alx_hw *hw, u16 clk_sel);

#define alx_get_readrq(_hw) pcie_get_readrq((_hw)->pdev)
#define alx_set_readrq(_hw, _v) pcie_set_readrq((_hw)->pdev, _v)


/* some issues are relavant to specific platforms
 * we assign those patches for the chip by pci device id
 * vendor id, subsystem id and revision number
 */
struct alx_platform_patch {
	u16 pci_did;
	u8  pci_rev;
	u16 subsystem_vid;
	u16 subsystem_did;
	u32 pflag;
};
/* PHY link issue */
#define ALX_PF_LINK		0x00001
/* Hibernatation issue */
#define ALX_PF_HIB		0x00002
/* not care revision number */
#define ALX_PF_ANY_REV		0x10000


void alx_patch_assign(struct alx_hw *hw);
bool alx_get_phy_info(struct alx_hw *hw);

#endif

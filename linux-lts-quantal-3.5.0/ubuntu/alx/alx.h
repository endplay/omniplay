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

#ifndef _ALX_H_
#define _ALX_H_

#define ALX_WATCHDOG_TIME   (5 * HZ)

/* alx_ring_header is a single, contiguous block of memory space
 * used by the three descriptor rings (tpd, rfd, rrd)
 */
struct alx_ring_header {
	/* virt addr */
	void        *desc;
	/* phy addr */
	dma_addr_t   dma;
	u32          size;
};

/* alx_buffer wraps around a pointer to a socket buffer
 * so a DMA physical address can be stored along with the skb
 */
struct alx_buffer {
	struct sk_buff *skb;
	/* DMA address */
	DEFINE_DMA_UNMAP_ADDR(dma);
	/* buffer size */
	DEFINE_DMA_UNMAP_LEN(size);
	/* information of this buffer */
	u16		flags;
};
#define ALX_BUF_TX_FIRSTFRAG	0x1

/* rx queue */
struct alx_rx_queue {
	struct net_device *netdev;
	/* device pointer for dma operation */
	struct device *dev;
	/* rrd ring virtual addr */
	struct rrd_desc *rrd_hdr;
	/* rrd ring physical addr */
	dma_addr_t rrd_dma;
	/* rfd ring virtual addr */
	struct rfd_desc *rfd_hdr;
	/* rfd ring physical addr */
	dma_addr_t rfd_dma;
	/* info for rx-skbs */
	struct alx_buffer *bf_info;

	/* number of ring elements */
	u16 count;
	/* rfd producer index */
	u16 pidx;
	/* rfd consumer index */
	u16 cidx;
	u16 rrd_cidx;
	/* register saving producer index */
	u16 p_reg;
	/* register saving consumer index */
	u16 c_reg;
	/* queue index */
	u16 qidx;
	unsigned long flag;

	struct sk_buff_head list;
};
#define ALX_RQ_USING		1
#define ALX_RX_ALLOC_THRESH	32

/* tx queue */
struct alx_tx_queue {
	struct net_device *netdev;
	/* device pointer for dma operation */
	struct device *dev;
	/* tpd ring virtual addr */
	struct tpd_desc *tpd_hdr;
	dma_addr_t tpd_dma;
	/* info for tx-skbs pending on HW */
	struct alx_buffer *bf_info;
	/* number of ring elements  */
	u16 count;
	/* producer index */
	u16 pidx;
	/* consumer index */
	atomic_t cidx;
	/* register saving producer index */
	u16 p_reg;
	/* register saving consumer index */
	u16 c_reg;
	/* queue index */
	u16 qidx;
};

#define ALX_TX_WAKEUP_THRESH(_tq) ((_tq)->count / 4)
#define ALX_DEFAULT_TX_WORK		128

struct alx_napi {
	struct napi_struct	napi;
	struct alx_adapter	*adpt;
	struct alx_rx_queue	*rxq;
	struct alx_tx_queue	*txq;
	int			vec_idx;
	u32			vec_mask;
	char			irq_lbl[IFNAMSIZ];
};

enum ALX_FLAGS {
	ALX_FLAG_USING_MSIX = 0,
	ALX_FLAG_USING_MSI,
	ALX_FLAG_RESETING,
	ALX_FLAG_TESTING,
	ALX_FLAG_HALT,
	ALX_FLAG_FPGA,
	ALX_FLAG_TASK_PENDING,
	ALX_FLAG_TASK_CHK_LINK,
	ALX_FLAG_TASK_RESET,
	ALX_FLAG_TASK_UPDATE_SMB,

	ALX_FLAG_NUMBER_OF_FLAGS,
};


struct alx_hw;
/*
 *board specific private data structure
 */
struct alx_adapter {
	struct net_device	*netdev;
	struct pci_dev		*pdev;

	struct alx_hw		hw;

	u16			bd_number;

	/* totally msix vectors */
	int			nr_vec;
	struct msix_entry	*msix_ent;

	/* all descriptor memory */
	struct alx_ring_header	ring_header;
	int			tx_ringsz;
	int			rx_ringsz;
	int			rxbuf_size;

	struct alx_napi		*qnapi[8];
	/* number of napi for TX-Q */
	int			nr_txq;
	/* number of napi for RX-Q */
	int			nr_rxq;
	/* number independent hw RX-Q */
	int			nr_hwrxq;
	/* total napi for TX-Q/RX-Q */
	int			nr_napi;

	/* lock for updating stats */
	spinlock_t		smb_lock;

	struct work_struct	task;
	struct net_device_stats net_stats;
	atomic_t		irq_sem;
	u16			msg_enable;

	unsigned long		flags;

	/* ethtool private flags */
	u32			eth_pflags;
	int			eth_diag_vect;
	int			eth_diag_cnt;
};


#define ALX_FLAG(_adpt, _FLAG) (\
	test_bit(ALX_FLAG_##_FLAG, &(_adpt)->flags))
#define ALX_FLAG_SET(_adpt, _FLAG) (\
	set_bit(ALX_FLAG_##_FLAG, &(_adpt)->flags))
#define ALX_FLAG_CLEAR(_adpt, _FLAG) (\
	clear_bit(ALX_FLAG_##_FLAG, &(_adpt)->flags))

static inline struct alx_rx_queue *alx_hw_rxq(struct alx_rx_queue *rxq)
{
	struct alx_adapter *adpt = netdev_priv(rxq->netdev);

	return ALX_CAP(&adpt->hw, MRQ) ? rxq : adpt->qnapi[0]->rxq;
}

/* needed by alx_ethtool.c */
extern void alx_configure(struct alx_adapter *adpt);
extern void alx_free_all_ring_resources(struct alx_adapter *adpt);
extern int alx_setup_all_ring_resources(struct alx_adapter *adpt);
extern void alx_init_def_rss_idt(struct alx_adapter *adpt);
extern int alx_alloc_rxring_buf(struct alx_adapter *adpt,
				struct alx_rx_queue *rxq);
extern void alx_init_intr(struct alx_adapter *adpt);
extern void alx_disable_advanced_intr(struct alx_adapter *adpt);
extern void alx_reinit(struct alx_adapter *adpt, bool in_task);
extern void alx_set_ethtool_ops(struct net_device *dev);
extern char alx_drv_name[];
extern char alx_drv_version[];

#endif

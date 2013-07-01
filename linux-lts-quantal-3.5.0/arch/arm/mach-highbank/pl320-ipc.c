/*
 * Copyright 2010 Calxeda, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/types.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/amba/bus.h>

#include <mach/pl320-ipc.h>

#define IPCMxSOURCE(m)		((m) * 0x40)
#define IPCMxDSET(m)		(((m) * 0x40) + 0x004)
#define IPCMxDCLEAR(m)		(((m) * 0x40) + 0x008)
#define IPCMxDSTATUS(m)		(((m) * 0x40) + 0x00C)
#define IPCMxMODE(m)		(((m) * 0x40) + 0x010)
#define IPCMxMSET(m)		(((m) * 0x40) + 0x014)
#define IPCMxMCLEAR(m)		(((m) * 0x40) + 0x018)
#define IPCMxMSTATUS(m)		(((m) * 0x40) + 0x01C)
#define IPCMxSEND(m)		(((m) * 0x40) + 0x020)
#define IPCMxDR(m, dr)		(((m) * 0x40) + ((dr) * 4) + 0x024)

#define IPCMMIS(irq)		(((irq) * 8) + 0x800)
#define IPCMRIS(irq)		(((irq) * 8) + 0x804)

#define MBOX_MASK(n)		(1 << (n))
#define IPC_FAST_MBOX		0
#define IPC_SLOW_MBOX		1
#define IPC_RX_MBOX		2

#define CHAN_MASK(n)		(1 << (n))
#define A9_SOURCE		1
#define M3_SOURCE		0

static void __iomem *ipc_base;
static int ipc_irq;
static DEFINE_SPINLOCK(ipc_m0_lock);
static DEFINE_MUTEX(ipc_m1_lock);
static DECLARE_COMPLETION(ipc_completion);
static ATOMIC_NOTIFIER_HEAD(ipc_notifier);

static inline void set_destination(int source, int mbox)
{
	__raw_writel(CHAN_MASK(source), ipc_base + IPCMxDSET(mbox));
	__raw_writel(CHAN_MASK(source), ipc_base + IPCMxMSET(mbox));
}

static inline void clear_destination(int source, int mbox)
{
	__raw_writel(CHAN_MASK(source), ipc_base + IPCMxDCLEAR(mbox));
	__raw_writel(CHAN_MASK(source), ipc_base + IPCMxMCLEAR(mbox));
}

static void __ipc_send(int mbox, u32 *data)
{
	int i;
	for (i = 0; i < 7; i++)
		__raw_writel(data[i], ipc_base + IPCMxDR(mbox, i));
	__raw_writel(0x1, ipc_base + IPCMxSEND(mbox));
}

static u32 __ipc_rcv(int mbox, u32 *data)
{
	int i;
	for (i = 0; i < 7; i++)
		data[i] = __raw_readl(ipc_base + IPCMxDR(mbox, i));
	return data[1];
}

/* non-blocking implementation from the A9 side, interrupt safe in theory */
int ipc_call_fast(u32 *data)
{
	int timeout, ret;

	spin_lock(&ipc_m0_lock);

	__ipc_send(IPC_FAST_MBOX, data);

	for (timeout = 5000; timeout > 0; timeout--) {
		if (__raw_readl(ipc_base + IPCMxSEND(IPC_FAST_MBOX)) == 0x2)
			break;
		udelay(100);
	}
	if (timeout == 0) {
		ret = -ETIMEDOUT;
		goto out;
	}

	ret = __ipc_rcv(IPC_FAST_MBOX, data);
out:
	__raw_writel(0, ipc_base + IPCMxSEND(IPC_FAST_MBOX));
	spin_unlock(&ipc_m0_lock);
	return ret;
}
EXPORT_SYMBOL(ipc_call_fast);

/* blocking implmentation from the A9 side, not usuable in interrupts! */
int ipc_call_slow(u32 *data)
{
	int ret;

	mutex_lock(&ipc_m1_lock);

	init_completion(&ipc_completion);
	__ipc_send(IPC_SLOW_MBOX, data);
	ret = wait_for_completion_timeout(&ipc_completion,
					  msecs_to_jiffies(1000));
	if (ret == 0)
		goto out;

	ret = __ipc_rcv(IPC_SLOW_MBOX, data);
out:
	mutex_unlock(&ipc_m1_lock);
	return ret;
}
EXPORT_SYMBOL(ipc_call_slow);

irqreturn_t ipc_handler(int irq, void *dev)
{
	u32 irq_stat;
	u32 data[7];

	irq_stat = __raw_readl(ipc_base + IPCMMIS(1));
	if (irq_stat & MBOX_MASK(IPC_SLOW_MBOX)) {
		__raw_writel(0, ipc_base + IPCMxSEND(IPC_SLOW_MBOX));
		complete(&ipc_completion);
	}
	if (irq_stat & MBOX_MASK(IPC_RX_MBOX)) {
		__ipc_rcv(IPC_RX_MBOX, data);
		atomic_notifier_call_chain(&ipc_notifier, data[0], data + 1);
		__raw_writel(2, ipc_base + IPCMxSEND(IPC_RX_MBOX));
	}

	return IRQ_HANDLED;
}

int pl320_ipc_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&ipc_notifier, nb);
}

int pl320_ipc_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&ipc_notifier, nb);
}

static int __devinit pl320_probe(struct amba_device *adev, const struct amba_id *id)
{
	int ret;

	ipc_base = ioremap(adev->res.start, resource_size(&adev->res));
	if (ipc_base == NULL)
		return -ENOMEM;

	__raw_writel(0, ipc_base + IPCMxSEND(IPC_FAST_MBOX));
	__raw_writel(0, ipc_base + IPCMxSEND(IPC_SLOW_MBOX));

	ipc_irq = adev->irq[0];
	ret = request_irq(ipc_irq, ipc_handler, 0, dev_name(&adev->dev), NULL);
	if (ret < 0)
		goto err;

	/* Init fast mailbox */
	__raw_writel(CHAN_MASK(A9_SOURCE), ipc_base + IPCMxSOURCE(IPC_FAST_MBOX));
	set_destination(M3_SOURCE, IPC_FAST_MBOX);

	/* Init slow mailbox */
	__raw_writel(CHAN_MASK(A9_SOURCE), ipc_base + IPCMxSOURCE(IPC_SLOW_MBOX));
	__raw_writel(CHAN_MASK(M3_SOURCE), ipc_base + IPCMxDSET(IPC_SLOW_MBOX));
	__raw_writel(CHAN_MASK(M3_SOURCE) | CHAN_MASK(A9_SOURCE),
		     ipc_base + IPCMxMSET(IPC_SLOW_MBOX));

	/* Init receive mailbox */
	__raw_writel(CHAN_MASK(M3_SOURCE), ipc_base + IPCMxSOURCE(IPC_RX_MBOX));
	__raw_writel(CHAN_MASK(A9_SOURCE), ipc_base + IPCMxDSET(IPC_RX_MBOX));
	__raw_writel(CHAN_MASK(M3_SOURCE) | CHAN_MASK(A9_SOURCE),
		     ipc_base + IPCMxMSET(IPC_RX_MBOX));

	return 0;
err:
	iounmap(ipc_base);
	return ret;
}

static struct amba_id pl320_ids[] = {
	{
		.id	= 0x00041320,
		.mask	= 0x000fffff,
	},
	{ 0, 0 },
};

static struct amba_driver pl320_driver = {
	.drv = {
		.name	= "pl320",
	},
	.id_table	= pl320_ids,
	.probe		= pl320_probe,
};

static int __init ipc_init(void)
{
	return amba_driver_register(&pl320_driver);
}
module_init(ipc_init);

irqreturn_t ipc_test_handler(int irq, void *dev)
{
	u32 irq_stat;

	irq_stat = __raw_readl(ipc_base + IPCMMIS(irq - (ipc_irq - 1)));
	if (irq_stat & MBOX_MASK(IPC_FAST_MBOX)) {
		if ((__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 0)) == 0x900dbeef) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 1)) == 1) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 2)) == 2) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 3)) == 3) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 4)) == 4) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 5)) == 5) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 6)) == 6)) {
			printk(KERN_ERR "ipc fast mbox message %X received\n", __raw_readl(ipc_base + IPCMxDR(IPC_FAST_MBOX, 0)));
			__raw_writel(0xBADBEEF, ipc_base + IPCMxDR(IPC_FAST_MBOX, 1));
		}
		__raw_writel(0x2, ipc_base + IPCMxSEND(IPC_FAST_MBOX));
	}
	if (irq_stat & MBOX_MASK(IPC_SLOW_MBOX)) {
		if ((__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 0)) == 0x12345678) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 1)) == 6) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 2)) == 5) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 3)) == 4) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 4)) == 3) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 5)) == 2) &&
		    (__raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 6)) == 1)) {
			printk("slow mbox message %X received\n", __raw_readl(ipc_base + IPCMxDR(IPC_SLOW_MBOX, 0)));
			__raw_writel(0x87654321, ipc_base + IPCMxDR(IPC_SLOW_MBOX, 1));
		}
		__raw_writel(0x2, ipc_base + IPCMxSEND(IPC_SLOW_MBOX));
	}
	if (irq_stat & MBOX_MASK(IPC_RX_MBOX)) {
		__raw_writel(0, ipc_base + IPCMxSEND(IPC_RX_MBOX));
		// handle events
	}

	return IRQ_HANDLED;
}

static void __init ipc_test(void)
{
	int ret, i;

	printk("ipc test start\n");

	for (i = 0; i < 8; i++) {
		u32 data[7];
		int j;
		if (i == 1) continue;

		if (request_irq(ipc_irq - 1 + i, ipc_test_handler, 0, "ipc", NULL) < 0) {
			printk("ipc - request_irq failed - FAIL\n");
			return;
		}

		set_destination(i, IPC_FAST_MBOX);
		set_destination(i, IPC_SLOW_MBOX);

		for (j = 1; j < 7; j++)
			data[j] = j;
		data[0] = 0x900dbeef;
		ret = ipc_call_fast(data);
		if (ret == 0xbadbeef)
			printk(KERN_ERR "ipc %d fast call - PASS\n", i);
		else
			printk(KERN_ERR "ipc %d fast call fail %d\n", i, ret);
		for (j = 1; j < 7; j++)
			data[j] = 7 - j;
		data[0] = 0x12345678;
		ret = ipc_call_slow(data);
		if (ret == 0x87654321)
			printk("ipc %d slow call - PASS\n", i);

		clear_destination(i, IPC_FAST_MBOX);
		clear_destination(i, IPC_SLOW_MBOX);

		free_irq(ipc_irq - 1 + i, NULL);
	}
	set_destination(M3_SOURCE, IPC_FAST_MBOX);
	set_destination(M3_SOURCE, IPC_SLOW_MBOX);
}
//late_initcall(ipc_test);


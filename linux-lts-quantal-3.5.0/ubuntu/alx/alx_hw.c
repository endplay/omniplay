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
#include <linux/pci.h>
#include <linux/crc32.h>
#include <linux/etherdevice.h>
#include <linux/mdio.h>

#include "alx_reg.h"
#include "alx_hw.h"

#define ALX_REV_A(_r) ((_r) == ALX_REV_A0 || (_r) == ALX_REV_A1)

/* get permanent mac address from */
int alx_get_perm_macaddr(struct alx_hw *hw, u8 *addr)
{
	u32 val, mac0, mac1;
	u16 flag, i;

#define INTN_LOADED 0x1
#define EXTN_LOADED 0x2

	flag = 0;
	val = 0;

read_mcadr:

	/* get it from register first */
	ALX_MEM_R32(hw, ALX_STAD0, &mac0);
	ALX_MEM_R32(hw, ALX_STAD1, &mac1);

	/* addr should be big-endian */
	*(__be32 *)(addr + 2) = cpu_to_be32(mac0);
	*(__be16 *)addr = cpu_to_be16((u16)mac1);

	if (is_valid_ether_addr(addr))
		return 0;

	if ((flag & INTN_LOADED) == 0) {
		/* load from efuse ? */
		for (i = 0; i < ALX_SLD_MAX_TO; i++) {
			ALX_MEM_R32(hw, ALX_SLD, &val);
			if ((val & (ALX_SLD_STAT | ALX_SLD_START)) == 0)
				break;
			mdelay(1);
		}
		if (i == ALX_SLD_MAX_TO)
			goto out;
		ALX_MEM_W32(hw, ALX_SLD, val | ALX_SLD_START);
		for (i = 0; i < ALX_SLD_MAX_TO; i++) {
			mdelay(1);
			ALX_MEM_R32(hw, ALX_SLD, &val);
			if ((val & ALX_SLD_START) == 0)
				break;
		}
		if (i == ALX_SLD_MAX_TO)
			goto out;
		flag |= INTN_LOADED;
		goto read_mcadr;
	}

	if ((flag & EXTN_LOADED) == 0) {
		ALX_MEM_R32(hw, ALX_EFLD, &val);
		if ((val & (ALX_EFLD_F_EXIST | ALX_EFLD_E_EXIST)) != 0) {
			/* load from eeprom/flash ? */
			for (i = 0; i < ALX_SLD_MAX_TO; i++) {
				ALX_MEM_R32(hw, ALX_EFLD, &val);
				if ((val & (ALX_EFLD_STAT |
					    ALX_EFLD_START)) == 0) {
					break;
				}
				mdelay(1);
			}
			if (i == ALX_SLD_MAX_TO)
				goto out;
			ALX_MEM_W32(hw, ALX_EFLD, val | ALX_EFLD_START);
			for (i = 0; i < ALX_SLD_MAX_TO; i++) {
				mdelay(1);
				ALX_MEM_R32(hw, ALX_EFLD, &val);
				if ((val & ALX_EFLD_START) == 0)
					break;
			}
			if (i == ALX_SLD_MAX_TO)
				goto out;
			flag |= EXTN_LOADED;
			goto read_mcadr;
		}
	}

out:
	return ALX_ERR_ALOAD;
}

void alx_set_macaddr(struct alx_hw *hw, u8 *addr)
{
	u32 val;

	/* for example: 00-0B-6A-F6-00-DC * STAD0=6AF600DC, STAD1=000B */
	val = be32_to_cpu(*(__be32 *)(addr + 2));
	ALX_MEM_W32(hw, ALX_STAD0, val);
	val = be16_to_cpu(*(__be16 *)addr);
	ALX_MEM_W32(hw, ALX_STAD1, val);
}

void alx_add_mc_addr(struct alx_hw *hw, u8 *addr)
{
	u32 crc32, bit, reg;

	crc32 = ether_crc(ETH_ALEN, addr);

	/* The HASH Table  is a register array of 2 32-bit registers.
	 * It is treated like an array of 64 bits.  We want to set
	 * bit BitArray[hash_value]. So we figure out what register
	 * the bit is in, read it, OR in the new bit, then write
	 * back the new value.  The register is determined by the
	 * upper 7 bits of the hash value and the bit within that
	 * register are determined by the lower 5 bits of the value.
	 */
	reg = (crc32 >> 31) & 0x1;
	bit = (crc32 >> 26) & 0x1F;

	hw->mc_hash[reg] |= (0x1 << bit);
}

void alx_enable_osc(struct alx_hw *hw)
{
	u32 val;

	/* rising edge */
	ALX_MEM_R32(hw, ALX_MISC, &val);
	ALX_MEM_W32(hw, ALX_MISC, val & ~ALX_MISC_INTNLOSC_OPEN);
	ALX_MEM_W32(hw, ALX_MISC, val | ALX_MISC_INTNLOSC_OPEN);
}

void alx_reset_osc(struct alx_hw *hw, u8 rev)
{
	u32 val, val2;

	/* clear Internal OSC settings, switching OSC by hw itself */
	ALX_MEM_R32(hw, ALX_MISC3, &val);
	ALX_MEM_W32(hw, ALX_MISC3,
		(val & ~ALX_MISC3_25M_BY_SW) | ALX_MISC3_25M_NOTO_INTNL);

	/* 25M clk from chipset may be unstable 1s after de-assert of
	 * PERST, driver need re-calibrate before enter Sleep for WoL
	 */
	ALX_MEM_R32(hw, ALX_MISC, &val);
	if (rev >= ALX_REV_B0) {
		/* restore over current protection def-val,
		 * this val could be reset by MAC-RST
		 */
		FIELD_SET32(val, ALX_MISC_PSW_OCP, ALX_MISC_PSW_OCP_DEF);
		/* a 0->1 change will update the internal val of osc */
		val &= ~ALX_MISC_INTNLOSC_OPEN;
		ALX_MEM_W32(hw, ALX_MISC, val);
		ALX_MEM_W32(hw, ALX_MISC, val | ALX_MISC_INTNLOSC_OPEN);
		/* hw will automatically dis OSC after cab. */
		ALX_MEM_R32(hw, ALX_MSIC2, &val2);
		val2 &= ~ALX_MSIC2_CALB_START;
		ALX_MEM_W32(hw, ALX_MSIC2, val2);
		ALX_MEM_W32(hw, ALX_MSIC2, val2 | ALX_MSIC2_CALB_START);
	} else {
		val &= ~ALX_MISC_INTNLOSC_OPEN;
		/* disable isoloate for A0 */
		if (ALX_REV_A(rev))
			val &= ~ALX_MISC_ISO_EN;

		ALX_MEM_W32(hw, ALX_MISC, val | ALX_MISC_INTNLOSC_OPEN);
		ALX_MEM_W32(hw, ALX_MISC, val);
	}

	udelay(20);
}

int alx_reset_mac(struct alx_hw *hw)
{
	u32 val, pmctrl;
	int i, ret;
	u8 rev;
	bool a_cr;

	pmctrl = 0;
	rev = (u8)ALX_REVID(hw);
	a_cr = ALX_REV_A(rev) && ALX_WITH_CR(hw);

	/* disable all interrupts, RXQ/TXQ */
	ALX_MEM_W32(hw, ALX_MSIX_MASK, 0xFFFFFFFF);
	ALX_MEM_W32(hw, ALX_IMR, 0);
	ALX_MEM_W32(hw, ALX_ISR, ALX_ISR_DIS);

	ret = alx_stop_mac(hw);
	if (ret)
		return ret;

	/* mac reset workaroud */
	ALX_MEM_W32(hw, ALX_RFD_PIDX, 1);

	/* dis l0s/l1 before mac reset */
	if (a_cr) {
		ALX_MEM_R32(hw, ALX_PMCTRL, &pmctrl);
		if ((pmctrl & (ALX_PMCTRL_L1_EN | ALX_PMCTRL_L0S_EN)) != 0) {
			ALX_MEM_W32(hw, ALX_PMCTRL,
				    pmctrl & ~(ALX_PMCTRL_L1_EN |
					       ALX_PMCTRL_L0S_EN));
		}
	}

	/* reset whole mac safely */
	ALX_MEM_R32(hw, ALX_MASTER, &val);
	ALX_MEM_W32(hw, ALX_MASTER,
		    val | ALX_MASTER_DMA_MAC_RST | ALX_MASTER_OOB_DIS);

	/* make sure it's real idle */
	udelay(10);
	for (i = 0; i < ALX_DMA_MAC_RST_TO; i++) {
		ALX_MEM_R32(hw, ALX_RFD_PIDX, &val);
		if (val == 0)
			break;
		udelay(10);
	}
	for (; i < ALX_DMA_MAC_RST_TO; i++) {
		ALX_MEM_R32(hw, ALX_MASTER, &val);
		if ((val & ALX_MASTER_DMA_MAC_RST) == 0)
			break;
		udelay(10);
	}
	if (i == ALX_DMA_MAC_RST_TO)
		return ALX_ERR_RSTMAC;
	udelay(10);

	if (a_cr) {
		/* set ALX_MASTER_PCLKSEL_SRDS (affect by soft-rst, PERST) */
		ALX_MEM_W32(hw, ALX_MASTER, val | ALX_MASTER_PCLKSEL_SRDS);
		/* resoter l0s / l1 */
		if (pmctrl & (ALX_PMCTRL_L1_EN | ALX_PMCTRL_L0S_EN))
			ALX_MEM_W32(hw, ALX_PMCTRL, pmctrl);
	}

	alx_reset_osc(hw, rev);
	/* clear Internal OSC settings, switching OSC by hw itself,
	 * disable isoloate for A version
	 */
	ALX_MEM_R32(hw, ALX_MISC3, &val);
	ALX_MEM_W32(hw, ALX_MISC3,
		    (val & ~ALX_MISC3_25M_BY_SW) | ALX_MISC3_25M_NOTO_INTNL);
	ALX_MEM_R32(hw, ALX_MISC, &val);
	val &= ~ALX_MISC_INTNLOSC_OPEN;
	if (ALX_REV_A(rev))
		val &= ~ALX_MISC_ISO_EN;
	ALX_MEM_W32(hw, ALX_MISC, val);
	udelay(20);

	/* driver control speed/duplex, hash-alg */
	ALX_MEM_W32(hw, ALX_MAC_CTRL, hw->rx_ctrl);

	/* clk sw */
	ALX_MEM_R32(hw, ALX_SERDES, &val);
	ALX_MEM_W32(hw, ALX_SERDES,
		val | ALX_SERDES_MACCLK_SLWDWN | ALX_SERDES_PHYCLK_SLWDWN);

	/* mac reset cause MDIO ctrl restore non-polling status */
	if (hw->is_fpga)
		__alx_start_phy_polling(hw, ALX_MDIO_CLK_SEL_25MD128);


	return ret;
}

/* alx_reset_phy
 *     completely reset phy, all settings/workaround will be re-configureed
 *     hib_en: enable/disable hibernation on PHY
 */
void alx_reset_phy(struct alx_hw *hw, bool hib_en)
{
	int i;
	u32 val;
	u16 phy_val;

	/* (DSP)reset PHY core */
	ALX_MEM_R32(hw, ALX_PHY_CTRL, &val);
	val &= ~(ALX_PHY_CTRL_DSPRST_OUT | ALX_PHY_CTRL_IDDQ |
		 ALX_PHY_CTRL_GATE_25M | ALX_PHY_CTRL_POWER_DOWN |
		 ALX_PHY_CTRL_CLS);
	val |= ALX_PHY_CTRL_RST_ANALOG;

	if (hib_en)
		val |= (ALX_PHY_CTRL_HIB_PULSE | ALX_PHY_CTRL_HIB_EN);
	else
		val &= ~(ALX_PHY_CTRL_HIB_PULSE | ALX_PHY_CTRL_HIB_EN);
	ALX_MEM_W32(hw, ALX_PHY_CTRL, val);
	udelay(10);
	ALX_MEM_W32(hw, ALX_PHY_CTRL, val | ALX_PHY_CTRL_DSPRST_OUT);

	/* delay 800us */
	for (i = 0; i < ALX_PHY_CTRL_DSPRST_TO; i++)
		udelay(10);

	if (hw->is_fpga)
		goto set_imr;

	/* phy power saving & hib */
	if (hib_en) {
		alx_write_phy_dbg(hw, ALX_MIIDBG_LEGCYPS, ALX_LEGCYPS_DEF);
		alx_write_phy_dbg(hw, ALX_MIIDBG_SYSMODCTRL,
			ALX_SYSMODCTRL_IECHOADJ_DEF);
		alx_write_phy_ext(hw, ALX_MIIEXT_PCS, ALX_MIIEXT_VDRVBIAS,
			ALX_VDRVBIAS_DEF);
	} else {
		alx_write_phy_dbg(hw, ALX_MIIDBG_LEGCYPS,
			ALX_LEGCYPS_DEF & ~ALX_LEGCYPS_EN);
		alx_write_phy_dbg(hw, ALX_MIIDBG_HIBNEG, ALX_HIBNEG_NOHIB);
		alx_write_phy_dbg(hw, ALX_MIIDBG_GREENCFG, ALX_GREENCFG_DEF);
	}

	/* EEE advertisement */
	if (ALX_CAP(hw, AZ)) {
		alx_write_phy_ext(hw, ALX_MIIEXT_ANEG,
			ALX_MIIEXT_LOCAL_EEEADV,
			ALX_CAP(hw, GIGA) ?
			ALX_LOCAL_EEEADV_1000BT | ALX_LOCAL_EEEADV_100BT :
			ALX_LOCAL_EEEADV_100BT);
		/* half amplify */
		alx_write_phy_dbg(hw, ALX_MIIDBG_AZ_ANADECT,
			ALX_AZ_ANADECT_DEF);
	} else {
		ALX_MEM_R32(hw, ALX_LPI_CTRL, &val);
		ALX_MEM_W32(hw, ALX_LPI_CTRL, val & ~ALX_LPI_CTRL_EN);
		alx_write_phy_ext(hw, ALX_MIIEXT_ANEG,
			ALX_MIIEXT_LOCAL_EEEADV, 0);
	}

	/* phy power saving */
	alx_write_phy_dbg(hw, ALX_MIIDBG_TST10BTCFG, ALX_TST10BTCFG_DEF);
	alx_write_phy_dbg(hw, ALX_MIIDBG_SRDSYSMOD, ALX_SRDSYSMOD_DEF);
	alx_write_phy_dbg(hw, ALX_MIIDBG_TST100BTCFG, ALX_TST100BTCFG_DEF);
	alx_write_phy_dbg(hw, ALX_MIIDBG_ANACTRL, ALX_ANACTRL_DEF);
	alx_read_phy_dbg(hw, ALX_MIIDBG_GREENCFG2, &phy_val);
	alx_write_phy_dbg(hw, ALX_MIIDBG_GREENCFG2,
		phy_val & ~ALX_GREENCFG2_GATE_DFSE_EN);
	/* rtl8139c, 120m issue */
	alx_write_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_NLP78,
		ALX_MIIEXT_NLP78_120M_DEF);
	alx_write_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_S3DIG10,
		ALX_MIIEXT_S3DIG10_DEF);

	if (hw->lnk_patch) {
		/* Turn off half amplitude */
		alx_read_phy_ext(hw, ALX_MIIEXT_PCS, ALX_MIIEXT_CLDCTRL3,
			&phy_val);
		alx_write_phy_ext(hw, ALX_MIIEXT_PCS, ALX_MIIEXT_CLDCTRL3,
			      phy_val | ALX_CLDCTRL3_BP_CABLE1TH_DET_GT);
		/* Turn off Green feature */
		alx_read_phy_dbg(hw, ALX_MIIDBG_GREENCFG2, &phy_val);
		alx_write_phy_dbg(hw, ALX_MIIDBG_GREENCFG2,
				 phy_val | ALX_GREENCFG2_BP_GREEN);
		/* Turn off half Bias */
		alx_read_phy_ext(hw, ALX_MIIEXT_PCS, ALX_MIIEXT_CLDCTRL5,
			&phy_val);
		alx_write_phy_ext(hw, ALX_MIIEXT_PCS, ALX_MIIEXT_CLDCTRL5,
			      phy_val | ALX_CLDCTRL5_BP_VD_HLFBIAS);
	}

set_imr:
	/* set phy interrupt mask */
	alx_write_phy_reg(hw, ALX_MII_IER,
		ALX_IER_LINK_UP | ALX_IER_LINK_DOWN);
}

#define ALX_PCI_CMD	(\
	PCI_COMMAND_MASTER |\
	PCI_COMMAND_MEMORY |\
	PCI_COMMAND_IO)
/*
 * alx_reset_pcie
 *   reset pcie relative registers (pci command, clk, aspm...)
 */
void alx_reset_pcie(struct alx_hw *hw)
{
	u32 val;
	u16 val16;
	u8 rev = (u8)ALX_REVID(hw);

	/* Workaround for PCI problem when BIOS sets MMRBC incorrectly. */
	ALX_CFG_R16(hw, PCI_COMMAND, &val16);
	if (!(val16 & ALX_PCI_CMD) || (val16 & PCI_COMMAND_INTX_DISABLE)) {
		val16 = (val16 | ALX_PCI_CMD) & ~PCI_COMMAND_INTX_DISABLE;
		ALX_CFG_W16(hw, PCI_COMMAND, val16);
	}

	/* clear WoL setting/status */
	ALX_MEM_R32(hw, ALX_WOL0, &val);
	ALX_MEM_W32(hw, ALX_WOL0, 0);

	/* deflt val of PDLL D3PLLOFF */
	ALX_MEM_R32(hw, ALX_PDLL_TRNS1, &val);
	ALX_MEM_W32(hw, ALX_PDLL_TRNS1, val & ~ALX_PDLL_TRNS1_D3PLLOFF_EN);

	/* mask some pcie error bits */
	ALX_MEM_R32(hw, ALX_UE_SVRT, &val);
	val &= ~(ALX_UE_SVRT_DLPROTERR | ALX_UE_SVRT_FCPROTERR);
	ALX_MEM_W32(hw, ALX_UE_SVRT, val);

	/* wol 25M  & pclk */
	ALX_MEM_R32(hw, ALX_MASTER, &val);
	if (ALX_REV_A(rev) && ALX_WITH_CR(hw)) {
		if ((val & ALX_MASTER_WAKEN_25M) == 0 ||
		    (val & ALX_MASTER_PCLKSEL_SRDS) == 0) {
			ALX_MEM_W32(hw, ALX_MASTER,
				    val | ALX_MASTER_PCLKSEL_SRDS |
				    ALX_MASTER_WAKEN_25M);
		}
	} else {
		if ((val & ALX_MASTER_WAKEN_25M) == 0 ||
		    (val & ALX_MASTER_PCLKSEL_SRDS) != 0) {
			ALX_MEM_W32(hw, ALX_MASTER,
				    (val & ~ALX_MASTER_PCLKSEL_SRDS) |
				    ALX_MASTER_WAKEN_25M);
		}
	}

	/* ASPM setting */
	alx_enable_aspm(hw, ALX_CAP(hw, L0S), ALX_CAP(hw, L1));

	udelay(10);
}

/* alx_stop_mac
 *     stop the mac, transmit & receive modules
 * return : 0 if ok, none-0 if busy
 */
int alx_stop_mac(struct alx_hw *hw)
{
	u32 rxq, txq, val;
	u16 i;

	ALX_MEM_R32(hw, ALX_RXQ0, &rxq);
	ALX_MEM_W32(hw, ALX_RXQ0, rxq & ~ALX_RXQ0_EN);
	ALX_MEM_R32(hw, ALX_TXQ0, &txq);
	ALX_MEM_W32(hw, ALX_TXQ0, txq & ~ALX_TXQ0_EN);

	udelay(40);

	hw->rx_ctrl &= ~(ALX_MAC_CTRL_RX_EN | ALX_MAC_CTRL_TX_EN);
	ALX_MEM_W32(hw, ALX_MAC_CTRL, hw->rx_ctrl);

	for (i = 0; i < ALX_DMA_MAC_RST_TO; i++) {
		ALX_MEM_R32(hw, ALX_MAC_STS, &val);
		if (!(val & ALX_MAC_STS_IDLE))
			break;
		udelay(10);
	}

	return (ALX_DMA_MAC_RST_TO == i) ? ALX_ERR_RSTMAC : 0;
}

/* alx_start_mac
 *     enable rx/tx MAC module
 */
void alx_start_mac(struct alx_hw *hw)
{
	u32 mac, txq, rxq;

	ALX_MEM_R32(hw, ALX_RXQ0, &rxq);
	ALX_MEM_W32(hw, ALX_RXQ0, rxq | ALX_RXQ0_EN);
	ALX_MEM_R32(hw, ALX_TXQ0, &txq);
	ALX_MEM_W32(hw, ALX_TXQ0, txq | ALX_TXQ0_EN);

	mac = hw->rx_ctrl;
	if (hw->link_duplex == FULL_DUPLEX)
		mac |= ALX_MAC_CTRL_FULLD;
	else
		mac &= ~ALX_MAC_CTRL_FULLD;
	FIELD_SET32(mac, ALX_MAC_CTRL_SPEED, hw->link_speed == SPEED_1000 ?
		   ALX_MAC_CTRL_SPEED_1000 : ALX_MAC_CTRL_SPEED_10_100);
	mac |= ALX_MAC_CTRL_TX_EN | ALX_MAC_CTRL_RX_EN;
	hw->rx_ctrl = mac;
	ALX_MEM_W32(hw, ALX_MAC_CTRL, mac);
}

/* set flow control on MAC side */
void alx_cfg_mac_fc(struct alx_hw *hw, u8 fc)
{
	if (fc & ALX_FC_RX)
		hw->rx_ctrl |= ALX_MAC_CTRL_RXFC_EN;
	else
		hw->rx_ctrl &= ~ALX_MAC_CTRL_RXFC_EN;

	if (fc & ALX_FC_TX)
		hw->rx_ctrl |= ALX_MAC_CTRL_TXFC_EN;
	else
		hw->rx_ctrl &= ~ALX_MAC_CTRL_TXFC_EN;

	ALX_MEM_W32(hw, ALX_MAC_CTRL, hw->rx_ctrl);
}

/* enable/disable aspm support */
void alx_enable_aspm(struct alx_hw *hw, bool l0s_en, bool l1_en)
{
	u32 pmctrl;
	u8 rev = (u8)ALX_REVID(hw);

	ALX_MEM_R32(hw, ALX_PMCTRL, &pmctrl);

	FIELD_SET32(pmctrl, ALX_PMCTRL_LCKDET_TIMER,
		   ALX_PMCTRL_LCKDET_TIMER_DEF);
	pmctrl |= ALX_PMCTRL_RCVR_WT_1US    |
		  ALX_PMCTRL_L1_CLKSW_EN    |
		  ALX_PMCTRL_L1_SRDSRX_PWD  ;
	FIELD_SET32(pmctrl, ALX_PMCTRL_L1REQ_TO, ALX_PMCTRL_L1REG_TO_DEF);
	FIELD_SET32(pmctrl, ALX_PMCTRL_L1_TIMER, ALX_PMCTRL_L1_TIMER_16US);
	pmctrl &= ~(ALX_PMCTRL_L1_SRDS_EN |
		    ALX_PMCTRL_L1_SRDSPLL_EN |
		    ALX_PMCTRL_L1_BUFSRX_EN |
		    ALX_PMCTRL_SADLY_EN |
		    ALX_PMCTRL_HOTRST_WTEN|
		    ALX_PMCTRL_L0S_EN |
		    ALX_PMCTRL_L1_EN |
		    ALX_PMCTRL_ASPM_FCEN |
		    ALX_PMCTRL_TXL1_AFTER_L0S |
		    ALX_PMCTRL_RXL1_AFTER_L0S
		    );
	if (ALX_REV_A(rev) && ALX_WITH_CR(hw))
		pmctrl |= ALX_PMCTRL_L1_SRDS_EN | ALX_PMCTRL_L1_SRDSPLL_EN;

	if (l0s_en)
		pmctrl |= (ALX_PMCTRL_L0S_EN | ALX_PMCTRL_ASPM_FCEN);
	if (l1_en)
		pmctrl |= (ALX_PMCTRL_L1_EN | ALX_PMCTRL_ASPM_FCEN);

	ALX_MEM_W32(hw, ALX_PMCTRL, pmctrl);
}


/* translate ethtool adv /speed/duplex settting to hw specific value */
u32 ethadv_to_hw_cfg(struct alx_hw *hw, u32 ethadv_cfg)
{
	u32 cfg = 0;

	if (ethadv_cfg & ADVERTISED_Autoneg) {
		cfg |= ALX_DRV_PHY_AUTO;
		if (ethadv_cfg & ADVERTISED_10baseT_Half)
			cfg |= ALX_DRV_PHY_10;
		if (ethadv_cfg & ADVERTISED_10baseT_Full)
			cfg |= ALX_DRV_PHY_10 | ALX_DRV_PHY_DUPLEX;
		if (ethadv_cfg & ADVERTISED_100baseT_Half)
			cfg |= ALX_DRV_PHY_100;
		if (ethadv_cfg & ADVERTISED_100baseT_Full)
			cfg |= ALX_DRV_PHY_100 | ALX_DRV_PHY_DUPLEX;
		if (ethadv_cfg & ADVERTISED_1000baseT_Half)
			cfg |= ALX_DRV_PHY_1000;
		if (ethadv_cfg & ADVERTISED_1000baseT_Full)
			cfg |= ALX_DRV_PHY_100 | ALX_DRV_PHY_DUPLEX;
		if (ethadv_cfg & ADVERTISED_Pause)
			cfg |= ADVERTISE_PAUSE_CAP;
		if (ethadv_cfg & ADVERTISED_Asym_Pause)
			cfg |= ADVERTISE_PAUSE_ASYM;
		if (ALX_CAP(hw, AZ))
			cfg |= ALX_DRV_PHY_EEE;
	} else {
		switch (ethadv_cfg) {
		case ADVERTISED_10baseT_Half:
			cfg |= ALX_DRV_PHY_10;
			break;
		case ADVERTISED_100baseT_Half:
			cfg |= ALX_DRV_PHY_100;
			break;
		case ADVERTISED_10baseT_Full:
			cfg |= ALX_DRV_PHY_10 | ALX_DRV_PHY_DUPLEX;
			break;
		case ADVERTISED_100baseT_Full:
			cfg |= ALX_DRV_PHY_100 | ALX_DRV_PHY_DUPLEX;
			break;
		}
	}

	return cfg;
}

/* initialize phy for speed / flow control
 * ethadv:
 *    format from ethtool, we use it for both autoneg and force mode
 */
int alx_setup_speed_duplex(struct alx_hw *hw, u32 ethadv, u8 flowctrl)
{
	u16 adv, giga, cr;
	u32 val;
	int err = 0;

	/* clear flag */
	alx_write_phy_reg(hw, ALX_MII_DBG_ADDR, 0);
	ALX_MEM_R32(hw, ALX_DRV, &val);
	FIELD_SET32(val, ALX_DRV_PHY, 0);

	if (ethadv & ADVERTISED_Autoneg) {
		adv = ADVERTISE_CSMA;
		adv |= ethtool_adv_to_mii_adv_t(ethadv);

		if (flowctrl & ALX_FC_ANEG) {
			if (flowctrl & ALX_FC_RX) {
				adv |= ADVERTISED_Pause;
				if (!(flowctrl & ALX_FC_TX))
					adv |= ADVERTISED_Asym_Pause;
			} else if (flowctrl & ALX_FC_TX)
				adv |= ADVERTISED_Asym_Pause;
		}
		giga = 0;
		if (ALX_CAP(hw, GIGA))
			giga = ethtool_adv_to_mii_ctrl1000_t(ethadv);

		cr = BMCR_RESET | BMCR_ANENABLE | BMCR_ANRESTART;

		if (alx_write_phy_reg(hw, MII_ADVERTISE, adv) ||
		    alx_write_phy_reg(hw, MII_CTRL1000, giga) ||
		    alx_write_phy_reg(hw, MII_BMCR, cr))
			err = ALX_ERR_MIIBUSY;
	} else {
		cr = BMCR_RESET;
		if (ethadv == ADVERTISED_100baseT_Half ||
		    ethadv == ADVERTISED_100baseT_Full)
			cr |= BMCR_SPEED100;
		if (ethadv == ADVERTISED_10baseT_Full ||
		    ethadv == ADVERTISED_100baseT_Full)
			cr |= BMCR_FULLDPLX;

		err = alx_write_phy_reg(hw, MII_BMCR, cr);
	}

	if (!err) {
		alx_write_phy_reg(hw, ALX_MII_DBG_ADDR, ALX_PHY_INITED);
		/* save config to HW */
		val |= ethadv_to_hw_cfg(hw, ethadv);
	}

	ALX_MEM_W32(hw, ALX_DRV, val);

	return err;
}


/* do post setting on phy if link up/down event occur */
void alx_post_phy_link(struct alx_hw *hw, u16 speed, bool az_en)
{
	u16 phy_val, len, agc;
	u8 revid = (u8)ALX_REVID(hw);
	bool adj_th;

	if (revid != ALX_REV_B0 &&
	    revid != ALX_REV_A1 &&
	    revid != ALX_REV_A0) {
		return;
	}
	adj_th = (revid == ALX_REV_B0) ? true : false;

	/* 1000BT/AZ, wrong cable length */
	if (speed != SPEED_0) {
		alx_read_phy_ext(hw, ALX_MIIEXT_PCS, ALX_MIIEXT_CLDCTRL6,
				 &phy_val);
		len = FIELD_GETX(phy_val, ALX_CLDCTRL6_CAB_LEN);
		alx_read_phy_dbg(hw, ALX_MIIDBG_AGC, &phy_val);
		agc = FIELD_GETX(phy_val, ALX_AGC_2_VGA);

		if ((speed == SPEED_1000 &&
		    (len > ALX_CLDCTRL6_CAB_LEN_SHORT1G ||
		    (0 == len && agc > ALX_AGC_LONG1G_LIMT))) ||
		    (speed == SPEED_100 &&
		    (len > ALX_CLDCTRL6_CAB_LEN_SHORT100M ||
		    (0 == len && agc > ALX_AGC_LONG100M_LIMT)))) {
			alx_write_phy_dbg(hw, ALX_MIIDBG_AZ_ANADECT,
					  ALX_AZ_ANADECT_LONG);
			alx_read_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_AFE,
					 &phy_val);
			alx_write_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_AFE,
					  phy_val | ALX_AFE_10BT_100M_TH);
		} else {
			alx_write_phy_dbg(hw, ALX_MIIDBG_AZ_ANADECT,
					  ALX_AZ_ANADECT_DEF);
			alx_read_phy_ext(hw, ALX_MIIEXT_ANEG,
					 ALX_MIIEXT_AFE, &phy_val);
			alx_write_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_AFE,
					  phy_val & ~ALX_AFE_10BT_100M_TH);
		}

		/* threashold adjust */
		if (adj_th && hw->lnk_patch) {
			if (speed == SPEED_100) {
				alx_write_phy_dbg(hw, ALX_MIIDBG_MSE16DB,
						  ALX_MSE16DB_UP);
			} else if (speed == SPEED_1000) {
				/*
				 * Giga link threshold, raise the tolerance of
				 * noise 50%
				 */
				alx_read_phy_dbg(hw, ALX_MIIDBG_MSE20DB,
						 &phy_val);
				FIELD_SETS(phy_val, ALX_MSE20DB_TH,
					   ALX_MSE20DB_TH_HI);
				alx_write_phy_dbg(hw, ALX_MIIDBG_MSE20DB,
						  phy_val);
			}
		}
		/* phy link-down in 1000BT/AZ mode */
		if (az_en && revid == ALX_REV_B0 && speed == SPEED_1000) {
			alx_write_phy_dbg(hw, ALX_MIIDBG_SRDSYSMOD,
				ALX_SRDSYSMOD_DEF & ~ALX_SRDSYSMOD_DEEMP_EN);
		}
	} else {
		alx_read_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_AFE,
				 &phy_val);
		alx_write_phy_ext(hw, ALX_MIIEXT_ANEG, ALX_MIIEXT_AFE,
				  phy_val & ~ALX_AFE_10BT_100M_TH);

		if (adj_th && hw->lnk_patch) {
			alx_write_phy_dbg(hw, ALX_MIIDBG_MSE16DB,
					  ALX_MSE16DB_DOWN);
			alx_read_phy_dbg(hw, ALX_MIIDBG_MSE20DB, &phy_val);
			FIELD_SETS(phy_val, ALX_MSE20DB_TH, ALX_MSE20DB_TH_DEF);
			alx_write_phy_dbg(hw, ALX_MIIDBG_MSE20DB, phy_val);
		}
		if (az_en && revid == ALX_REV_B0) {
			alx_write_phy_dbg(hw, ALX_MIIDBG_SRDSYSMOD,
					  ALX_SRDSYSMOD_DEF);
		}
	}
}


/* do power saving setting befor enter suspend mode
 * NOTE:
 *    1. phy link must be established before calling this function
 *    2. wol option (pattern,magic,link,etc.) is configed before call it.
 */
int alx_pre_suspend(struct alx_hw *hw, u16 speed)
{
	u32 master, mac, phy, val;
	int err = 0;

	ALX_MEM_R32(hw, ALX_MASTER, &master);
	master &= ~ALX_MASTER_PCLKSEL_SRDS;
	mac = hw->rx_ctrl;
	/* 10/100 half */
	FIELD_SET32(mac, ALX_MAC_CTRL_SPEED,  ALX_MAC_CTRL_SPEED_10_100);
	mac &= ~(ALX_MAC_CTRL_FULLD | ALX_MAC_CTRL_RX_EN | ALX_MAC_CTRL_TX_EN);

	ALX_MEM_R32(hw, ALX_PHY_CTRL, &phy);
	phy &= ~(ALX_PHY_CTRL_DSPRST_OUT | ALX_PHY_CTRL_CLS);
	phy |= ALX_PHY_CTRL_RST_ANALOG | ALX_PHY_CTRL_HIB_PULSE |
	       ALX_PHY_CTRL_HIB_EN;

	/* without any activity  */
	if (!(hw->sleep_ctrl & ALX_SLEEP_ACTIVE)) {
		err = alx_write_phy_reg(hw, ALX_MII_IER, 0);
		phy |= ALX_PHY_CTRL_IDDQ | ALX_PHY_CTRL_POWER_DOWN;
		goto config_reg;
	}

	if (hw->sleep_ctrl & (ALX_SLEEP_WOL_MAGIC | ALX_SLEEP_CIFS))
		mac |= ALX_MAC_CTRL_RX_EN | ALX_MAC_CTRL_BRD_EN;
	if (hw->sleep_ctrl & ALX_SLEEP_CIFS)
		mac |= ALX_MAC_CTRL_TX_EN;
	if (speed % 10 == FULL_DUPLEX)
		mac |= ALX_MAC_CTRL_FULLD;
	if (speed >= SPEED_1000)
		FIELD_SET32(mac, ALX_MAC_CTRL_SPEED, ALX_MAC_CTRL_SPEED_1000);
	phy |= ALX_PHY_CTRL_DSPRST_OUT;
	err = alx_write_phy_ext(hw, ALX_MIIEXT_ANEG,
		ALX_MIIEXT_S3DIG10, ALX_MIIEXT_S3DIG10_SL);
config_reg:

	if (!err) {
		alx_enable_osc(hw);
		hw->rx_ctrl = mac;
		ALX_MEM_W32(hw, ALX_MASTER, master);
		ALX_MEM_W32(hw, ALX_MAC_CTRL, mac);
		ALX_MEM_W32(hw, ALX_PHY_CTRL, phy);

		/* set val of PDLL D3PLLOFF */
		ALX_MEM_R32(hw, ALX_PDLL_TRNS1, &val);
		val |= ALX_PDLL_TRNS1_D3PLLOFF_EN;
		ALX_MEM_W32(hw, ALX_PDLL_TRNS1, val);
	}

	return err;
}

/* wait mdio module to be idle */
bool __alx_wait_mdio_idle(struct alx_hw *hw)
{
	u32 val;
	int i;

	for (i = 0; i < ALX_MDIO_MAX_AC_TO; i++) {
		ALX_MEM_R32(hw, ALX_MDIO, &val);
		if (!(val & ALX_MDIO_BUSY))
			break;
		udelay(10);
	}
	return i != ALX_MDIO_MAX_AC_TO;
}

void __alx_stop_phy_polling(struct alx_hw *hw)
{
	if (!hw->is_fpga)
		return;

	ALX_MEM_W32(hw, ALX_MDIO, 0);
	__alx_wait_mdio_idle(hw);
}

void __alx_start_phy_polling(struct alx_hw *hw, u16 clk_sel)
{
	u32 val;

	if (!hw->is_fpga)
		return;

	val = ALX_MDIO_SPRES_PRMBL |
	      FIELDX(ALX_MDIO_CLK_SEL, clk_sel) |
	      FIELDX(ALX_MDIO_REG, 1) |
	      ALX_MDIO_START |
	      ALX_MDIO_OP_READ;
	ALX_MEM_W32(hw, ALX_MDIO, val);
	__alx_wait_mdio_idle(hw);
	val |= ALX_MDIO_AUTO_POLLING;
	val &= ~ALX_MDIO_START;
	ALX_MEM_W32(hw, ALX_MDIO, val);
	udelay(30);
}

/* __alx_read_phy_core
 *     core function to read register in PHY via MDIO interface
 * ext: extension register (see IEEE 802.3)
 * dev: device address (see IEEE 802.3 DEVAD, PRTAD is fixed to 0)
 * reg: register to read
 */
int __alx_read_phy_core(struct alx_hw *hw, bool ext, u8 dev,
			     u16 reg, u16 *phy_data)
{
	u32 val, clk_sel;
	int err;

	__alx_stop_phy_polling(hw);

	*phy_data = 0;

	/* use slow clock when it's in hibernation status */
	clk_sel = !hw->link_up ?
		ALX_MDIO_CLK_SEL_25MD128 : ALX_MDIO_CLK_SEL_25MD4;

	if (ext) {
		val = FIELDX(ALX_MDIO_EXTN_DEVAD, dev) |
		      FIELDX(ALX_MDIO_EXTN_REG, reg);
		ALX_MEM_W32(hw, ALX_MDIO_EXTN, val);

		val = ALX_MDIO_SPRES_PRMBL |
		      FIELDX(ALX_MDIO_CLK_SEL, clk_sel) |
		      ALX_MDIO_START |
		      ALX_MDIO_MODE_EXT |
		      ALX_MDIO_OP_READ;
	} else {
		val = ALX_MDIO_SPRES_PRMBL |
		      FIELDX(ALX_MDIO_CLK_SEL, clk_sel) |
		      FIELDX(ALX_MDIO_REG, reg) |
		      ALX_MDIO_START |
		      ALX_MDIO_OP_READ;
	}
	ALX_MEM_W32(hw, ALX_MDIO, val);

	if (unlikely(!__alx_wait_mdio_idle(hw)))
		err = ALX_ERR_MIIBUSY;
	else {
		ALX_MEM_R32(hw, ALX_MDIO, &val);
		*phy_data = (u16)FIELD_GETX(val, ALX_MDIO_DATA);
		err = 0;
	}

	__alx_start_phy_polling(hw, clk_sel);

	return err;
}

/* __alx_write_phy_core
 *     core function to write to register in PHY via MDIO interface
 * ext: extension register (see IEEE 802.3)
 * dev: device address (see IEEE 802.3 DEVAD, PRTAD is fixed to 0)
 * reg: register to write
 */
int __alx_write_phy_core(struct alx_hw *hw, bool ext, u8 dev,
		       u16 reg, u16 phy_data)
{
	u32 val, clk_sel;
	int err = 0;

	__alx_stop_phy_polling(hw);

	/* use slow clock when it's in hibernation status */
	clk_sel = !hw->link_up ?
		ALX_MDIO_CLK_SEL_25MD128 : ALX_MDIO_CLK_SEL_25MD4;

	if (ext) {
		val = FIELDX(ALX_MDIO_EXTN_DEVAD, dev) |
		      FIELDX(ALX_MDIO_EXTN_REG, reg);
		ALX_MEM_W32(hw, ALX_MDIO_EXTN, val);

		val = ALX_MDIO_SPRES_PRMBL |
		      FIELDX(ALX_MDIO_CLK_SEL, clk_sel) |
		      FIELDX(ALX_MDIO_DATA, phy_data) |
		      ALX_MDIO_START |
		      ALX_MDIO_MODE_EXT;
	} else {
		val = ALX_MDIO_SPRES_PRMBL |
		      FIELDX(ALX_MDIO_CLK_SEL, clk_sel) |
		      FIELDX(ALX_MDIO_REG, reg) |
		      FIELDX(ALX_MDIO_DATA, phy_data) |
		      ALX_MDIO_START;
	}
	ALX_MEM_W32(hw, ALX_MDIO, val);

	if (unlikely(!__alx_wait_mdio_idle(hw)))
		err = ALX_ERR_MIIBUSY;

	__alx_start_phy_polling(hw, clk_sel);

	return err;
}

/* read from PHY normal register */
int __alx_read_phy_reg(struct alx_hw *hw, u16 reg, u16 *phy_data)
{
	return __alx_read_phy_core(hw, false, 0, reg, phy_data);
}

/* write to PHY normal register */
int __alx_write_phy_reg(struct alx_hw *hw, u16 reg, u16 phy_data)
{
	return __alx_write_phy_core(hw, false, 0, reg, phy_data);
}

/* read from PHY extension register */
int __alx_read_phy_ext(struct alx_hw *hw, u8 dev, u16 reg, u16 *pdata)
{
	return __alx_read_phy_core(hw, true, dev, reg, pdata);
}

/* write to PHY extension register */
int __alx_write_phy_ext(struct alx_hw *hw, u8 dev, u16 reg, u16 data)
{
	return __alx_write_phy_core(hw, true, dev, reg, data);
}

/* read from PHY debug port */
int __alx_read_phy_dbg(struct alx_hw *hw, u16 reg, u16 *pdata)
{
	int err;

	err = __alx_write_phy_reg(hw, ALX_MII_DBG_ADDR, reg);
	if (unlikely(err))
		return err;
	else
		err = __alx_read_phy_reg(hw, ALX_MII_DBG_DATA, pdata);

	return err;
}

/* write to PHY debug port */
int __alx_write_phy_dbg(struct alx_hw *hw, u16 reg, u16 data)
{
	int err;

	err = __alx_write_phy_reg(hw, ALX_MII_DBG_ADDR, reg);
	if (unlikely(err))
		return err;
	else
		err = __alx_write_phy_reg(hw, ALX_MII_DBG_DATA, data);

	return err;
}

int alx_read_phy_reg(struct alx_hw *hw, u16 reg, u16 *phy_data)
{
	int err;

	spin_lock(&hw->mdio_lock);
	err = __alx_read_phy_reg(hw, reg, phy_data);
	spin_unlock(&hw->mdio_lock);

	return err;
}

int alx_write_phy_reg(struct alx_hw *hw, u16 reg, u16 phy_data)
{
	int err;

	spin_lock(&hw->mdio_lock);
	err = __alx_write_phy_reg(hw, reg, phy_data);
	spin_unlock(&hw->mdio_lock);

	return err;
}

int alx_read_phy_ext(struct alx_hw *hw, u8 dev, u16 reg, u16 *pdata)
{
	int err;

	spin_lock(&hw->mdio_lock);
	err = __alx_read_phy_ext(hw, dev, reg, pdata);
	spin_unlock(&hw->mdio_lock);

	return err;
}

int alx_write_phy_ext(struct alx_hw *hw, u8 dev, u16 reg, u16 data)
{
	int err;

	spin_lock(&hw->mdio_lock);
	err = __alx_write_phy_ext(hw, dev, reg, data);
	spin_unlock(&hw->mdio_lock);

	return err;
}

int alx_read_phy_dbg(struct alx_hw *hw, u16 reg, u16 *pdata)
{
	int err;

	spin_lock(&hw->mdio_lock);
	err = __alx_read_phy_dbg(hw, reg, pdata);
	spin_unlock(&hw->mdio_lock);

	return err;
}

int alx_write_phy_dbg(struct alx_hw *hw, u16 reg, u16 data)
{
	int err;

	spin_lock(&hw->mdio_lock);
	err = __alx_write_phy_dbg(hw, reg, data);
	spin_unlock(&hw->mdio_lock);

	return err;
}

u16 alx_get_phy_config(struct alx_hw *hw)
{
	u32 val;
	u16 phy_val;

	ALX_MEM_R32(hw, ALX_PHY_CTRL, &val);
	/* phy in rst */
	if ((val & ALX_PHY_CTRL_DSPRST_OUT) == 0)
		return ALX_DRV_PHY_UNKNOWN;

	ALX_MEM_R32(hw, ALX_DRV, &val);
	val = FIELD_GETX(val, ALX_DRV_PHY);
	if (ALX_DRV_PHY_UNKNOWN == val)
		return ALX_DRV_PHY_UNKNOWN;

	alx_read_phy_reg(hw, ALX_MII_DBG_ADDR, &phy_val);
	if (ALX_PHY_INITED == phy_val)
		return (u16) val;

	return ALX_DRV_PHY_UNKNOWN;
}

bool alx_phy_configed(struct alx_hw *hw)
{
	u32 cfg, hw_cfg;

	cfg = ethadv_to_hw_cfg(hw, hw->adv_cfg);
	cfg = FIELD_GETX(cfg, ALX_DRV_PHY);
	hw_cfg = alx_get_phy_config(hw);
	if (hw_cfg == ALX_DRV_PHY_UNKNOWN)
		return false;

	return cfg == hw_cfg;
}

int alx_get_phy_link(struct alx_hw *hw, bool *link_up, u16 *speed)
{
	struct pci_dev *pdev = hw->pdev;
	u16 bmsr, giga;
	int err;

	err = alx_read_phy_reg(hw, MII_BMSR, &bmsr);
	err = alx_read_phy_reg(hw, MII_BMSR, &bmsr);
	if (unlikely(err))
		goto out;

	if (!(bmsr & BMSR_LSTATUS)) {
		*link_up = false;
		goto out;
	}

	*link_up = true;

	/* speed/duplex result is saved in PHY Specific Status Register */
	err = alx_read_phy_reg(hw, ALX_MII_GIGA_PSSR, &giga);
	if (unlikely(err))
		goto out;

	if (!(giga & ALX_GIGA_PSSR_SPD_DPLX_RESOLVED))
		goto wrong_spd_out;

	switch (giga & ALX_GIGA_PSSR_SPEED) {
	case ALX_GIGA_PSSR_1000MBS:
		*speed = SPEED_1000;
		break;
	case ALX_GIGA_PSSR_100MBS:
		*speed = SPEED_100;
		break;
	case ALX_GIGA_PSSR_10MBS:
		*speed = SPEED_10;
		break;
	default:
		goto wrong_spd_out;
	}
	*speed += (giga & ALX_GIGA_PSSR_DPLX) ? FULL_DUPLEX : HALF_DUPLEX;
	goto out;

wrong_spd_out:
	dev_err(&pdev->dev, "PHY SPD/DPLX unresolved :%x\n", giga);
	err = -EINVAL;
out:
	return err;
}

int alx_clear_phy_intr(struct alx_hw *hw)
{
	u16 isr;

	/* clear interrupt status by read it */
	return alx_read_phy_reg(hw, ALX_MII_ISR, &isr);
}

int alx_config_wol(struct alx_hw *hw)
{
	u32 wol;
	int err = 0;

	wol = 0;
	/* turn on magic packet event */
	if (hw->sleep_ctrl & ALX_SLEEP_WOL_MAGIC) {
		wol |= ALX_WOL0_MAGIC_EN | ALX_WOL0_PME_MAGIC_EN;
		/* magic packet maybe Broadcast&multicast&Unicast frame */
		/* mac |= MAC_CTRL_BC_EN; */
	}

	/* turn on link up event */
	if (hw->sleep_ctrl & ALX_SLEEP_WOL_PHY) {
		wol |=  ALX_WOL0_LINK_EN | ALX_WOL0_PME_LINK;
		/* only link up can wake up */
		err = alx_write_phy_reg(hw, ALX_MII_IER, ALX_IER_LINK_UP);
	}
	ALX_MEM_W32(hw, ALX_WOL0, wol);

	return err;
}

void alx_configure_rss(struct alx_hw *hw, bool en)
{
	u32 ctrl;
	int i;

	ALX_MEM_R32(hw, ALX_RXQ0, &ctrl);

	if (en) {
		for (i = 0; i < sizeof(hw->rss_key); i++) {
			/* rss key should be saved in chip with
			 * reversed order.
			 */
			int j = sizeof(hw->rss_key) - i - 1;

			ALX_MEM_W8(hw, ALX_RSS_KEY0 + j, hw->rss_key[i]);
		}

		for (i = 0; i < ARRAY_SIZE(hw->rss_idt); i++)
			ALX_MEM_W32(hw, ALX_RSS_IDT_TBL0 + i * 4,
				    hw->rss_idt[i]);

		FIELD_SET32(ctrl, ALX_RXQ0_RSS_HSTYP, hw->rss_hash_type);
		FIELD_SET32(ctrl, ALX_RXQ0_RSS_MODE, ALX_RXQ0_RSS_MODE_MQMI);
		FIELD_SET32(ctrl, ALX_RXQ0_IDT_TBL_SIZE, hw->rss_idt_size);
		ctrl |= ALX_RXQ0_RSS_HASH_EN;
	} else {
		ctrl &= ~ALX_RXQ0_RSS_HASH_EN;
	}

	ALX_MEM_W32(hw, ALX_RXQ0, ctrl);
}

void alx_configure_basic(struct alx_hw *hw)
{
	u32 val, raw_mtu, max_payload;
	u16 val16;
	u8 chip_rev = ALX_REVID(hw);

	/* mac address */
	alx_set_macaddr(hw, hw->mac_addr);

	/* clk gating */
	ALX_MEM_W32(hw, ALX_CLK_GATE, ALX_CLK_GATE_ALL_A0);

	/* idle timeout to switch clk_125M */
	if (chip_rev >= ALX_REV_B0) {
		ALX_MEM_W32(hw, ALX_IDLE_DECISN_TIMER,
			ALX_IDLE_DECISN_TIMER_DEF);
	}

	/* stats refresh timeout */
	ALX_MEM_W32(hw, ALX_SMB_TIMER, hw->smb_timer * 500UL);

	/* intr moduration */
	ALX_MEM_R32(hw, ALX_MASTER, &val);
	val = val | ALX_MASTER_IRQMOD2_EN |
		    ALX_MASTER_IRQMOD1_EN |
		    ALX_MASTER_SYSALVTIMER_EN;
	ALX_MEM_W32(hw, ALX_MASTER, val);
	ALX_MEM_W32(hw, ALX_IRQ_MODU_TIMER,
		    FIELDX(ALX_IRQ_MODU_TIMER1, hw->imt >> 1));
	/* intr re-trig timeout */
	ALX_MEM_W32(hw, ALX_INT_RETRIG, ALX_INT_RETRIG_TO);
	/* tpd threshold to trig int */
	ALX_MEM_W32(hw, ALX_TINT_TPD_THRSHLD, hw->ith_tpd);
	ALX_MEM_W32(hw, ALX_TINT_TIMER, hw->imt);

	/* mtu, 8:fcs+vlan */
	raw_mtu = hw->mtu + ETH_HLEN;
	ALX_MEM_W32(hw, ALX_MTU, raw_mtu + 8);
	if (raw_mtu > ALX_MTU_JUMBO_TH)
		hw->rx_ctrl &= ~ALX_MAC_CTRL_FAST_PAUSE;

	/* txq */
	if ((raw_mtu + 8) < ALX_TXQ1_JUMBO_TSO_TH)
		val = (raw_mtu + 8 + 7) >> 3;
	else
		val = ALX_TXQ1_JUMBO_TSO_TH >> 3;
	ALX_MEM_W32(hw, ALX_TXQ1, val | ALX_TXQ1_ERRLGPKT_DROP_EN);
	max_payload = alx_get_readrq(hw) >> 8;
	/*
	 * if BIOS had changed the default dma read max length,
	 * restore it to default value
	 */
	if (max_payload < ALX_DEV_CTRL_MAXRRS_MIN)
		alx_set_readrq(hw, 128 << ALX_DEV_CTRL_MAXRRS_MIN);

	val = FIELDX(ALX_TXQ0_TPD_BURSTPREF, ALX_TXQ_TPD_BURSTPREF_DEF) |
	      ALX_TXQ0_MODE_ENHANCE |
	      ALX_TXQ0_LSO_8023_EN |
	      ALX_TXQ0_SUPT_IPOPT |
	      FIELDX(ALX_TXQ0_TXF_BURST_PREF, ALX_TXQ_TXF_BURST_PREF_DEF);
	ALX_MEM_W32(hw, ALX_TXQ0, val);
	val = FIELDX(ALX_HQTPD_Q1_NUMPREF, ALX_TXQ_TPD_BURSTPREF_DEF) |
	      FIELDX(ALX_HQTPD_Q2_NUMPREF, ALX_TXQ_TPD_BURSTPREF_DEF) |
	      FIELDX(ALX_HQTPD_Q3_NUMPREF, ALX_TXQ_TPD_BURSTPREF_DEF) |
	      ALX_HQTPD_BURST_EN;
	ALX_MEM_W32(hw, ALX_HQTPD, val);

	/* rxq, flow control */
	ALX_MEM_R32(hw, ALX_SRAM5, &val);
	val = FIELD_GETX(val, ALX_SRAM_RXF_LEN) << 3;
	if (val > ALX_SRAM_RXF_LEN_8K) {
		val16 = ALX_MTU_STD_ALGN >> 3;
		val = (val - ALX_RXQ2_RXF_FLOW_CTRL_RSVD) >> 3;
	} else {
		val16 = ALX_MTU_STD_ALGN >> 3;
		val = (val - ALX_MTU_STD_ALGN) >> 3;
	}
	ALX_MEM_W32(hw, ALX_RXQ2,
		    FIELDX(ALX_RXQ2_RXF_XOFF_THRESH, val16) |
		    FIELDX(ALX_RXQ2_RXF_XON_THRESH, val));
	val = FIELDX(ALX_RXQ0_NUM_RFD_PREF, ALX_RXQ0_NUM_RFD_PREF_DEF) |
	      FIELDX(ALX_RXQ0_RSS_MODE, ALX_RXQ0_RSS_MODE_DIS) |
	      FIELDX(ALX_RXQ0_IDT_TBL_SIZE, ALX_RXQ0_IDT_TBL_SIZE_DEF) |
	      ALX_RXQ0_RSS_HSTYP_ALL |
	      ALX_RXQ0_RSS_HASH_EN |
	      ALX_RXQ0_IPV6_PARSE_EN;
	if (ALX_CAP(hw, GIGA)) {
		FIELD_SET32(val, ALX_RXQ0_ASPM_THRESH,
			    ALX_RXQ0_ASPM_THRESH_100M);
	}
	ALX_MEM_W32(hw, ALX_RXQ0, val);

	/* DMA */
	ALX_MEM_R32(hw, ALX_DMA, &val);
	val = FIELDX(ALX_DMA_RORDER_MODE, ALX_DMA_RORDER_MODE_OUT) |
	      ALX_DMA_RREQ_PRI_DATA |
	      FIELDX(ALX_DMA_RREQ_BLEN, max_payload) |
	      FIELDX(ALX_DMA_WDLY_CNT, ALX_DMA_WDLY_CNT_DEF) |
	      FIELDX(ALX_DMA_RDLY_CNT, ALX_DMA_RDLY_CNT_DEF) |
	      FIELDX(ALX_DMA_RCHNL_SEL, hw->dma_chnl - 1);
	ALX_MEM_W32(hw, ALX_DMA, val);

	/* multi-tx-q weight */
	if (ALX_CAP(hw, MTQ)) {
		val = FIELDX(ALX_WRR_PRI, hw->wrr_ctrl) |
		      FIELDX(ALX_WRR_PRI0, hw->wrr[0]) |
		      FIELDX(ALX_WRR_PRI1, hw->wrr[1]) |
		      FIELDX(ALX_WRR_PRI2, hw->wrr[2]) |
		      FIELDX(ALX_WRR_PRI3, hw->wrr[3]);
		ALX_MEM_W32(hw, ALX_WRR, val);
	}
}

void alx_mask_msix(struct alx_hw *hw, int index, bool mask)
{
	u32 reg, val;

	reg = ALX_MSIX_ENTRY_BASE + index * PCI_MSIX_ENTRY_SIZE +
		   PCI_MSIX_ENTRY_VECTOR_CTRL;

	val = mask ? PCI_MSIX_ENTRY_CTRL_MASKBIT : 0;

	ALX_MEM_W32(hw, reg, val);
	ALX_MEM_FLUSH(hw);
}

int alx_select_powersaving_speed(struct alx_hw *hw, u16 *speed)
{
	int i, err;
	u16 spd, lpa;
	bool linkup;

	err = alx_get_phy_link(hw, &linkup, &spd);
	if (err)
		goto out;

	if (!linkup) {
		*speed = SPEED_0;
		goto out;
	}

	err = alx_read_phy_reg(hw, MII_LPA, &lpa);
	if (err)
		goto out;

	if (!(lpa & LPA_LPACK)) {
		*speed = spd;
		goto out;
	}
	if (lpa & LPA_10FULL)
		*speed = SPEED_10 + FULL_DUPLEX;
	else if (lpa & LPA_10HALF)
		*speed = SPEED_10 + HALF_DUPLEX;
	else if (lpa & LPA_100FULL)
		*speed = SPEED_100 + FULL_DUPLEX;
	else
		*speed = SPEED_100 + HALF_DUPLEX;

	if (*speed != spd) {
		err = alx_write_phy_reg(hw, ALX_MII_IER, 0);
		if (err)
			goto out;
		err = alx_setup_speed_duplex(hw,
			ALX_SPEED_TO_ETHADV(*speed) | ADVERTISED_Autoneg,
			ALX_FC_ANEG | ALX_FC_RX | ALX_FC_TX);
		if (err)
			goto out;

		/* wait for linkup */
		for (i = 0; i < ALX_MAX_SETUP_LNK_CYCLE; i++) {
			u16 speed2;
			bool link_on;

			msleep(100);
			err = alx_get_phy_link(hw, &link_on, &speed2);
			if (err)
				goto out;
			if (link_on)
				break;
		}
		if (i == ALX_MAX_SETUP_LNK_CYCLE) {
			err = ALX_LINK_TIMEOUT;
			goto out;
		}
	}

out:
	return err;
}

void __alx_update_hw_stats(struct alx_hw *hw)
{
	u16 reg;
	u32 data;
	unsigned long *p;

	/* RX stats */
	reg = ALX_RX_STATS_BIN;
	p = &hw->stats.rx_ok;
	while (reg <=  ALX_RX_STATS_END) {
		ALX_MEM_R32(hw, reg, &data);
		*p++ += data;
		reg += 4;
	}

	/* TX stats */
	reg = ALX_TX_STATS_BIN;
	p = &hw->stats.tx_ok;
	while (reg <= ALX_TX_STATS_END) {
		ALX_MEM_R32(hw, reg, &data);
		*p++ += data;
		reg += 4;
	}
}

static const struct alx_platform_patch plats[] = {
{0x1091, 0x00, 0x1969, 0x0091, 0x1001},
{0},
};

void alx_patch_assign(struct alx_hw *hw)
{
	int i = 0;

	while (plats[i].pci_did != 0) {
		if (plats[i].pci_did == ALX_DID(hw) &&
		    plats[i].subsystem_vid == ALX_SUB_VID(hw) &&
		    plats[i].subsystem_did == ALX_SUB_DID(hw) &&
		    (plats[i].pflag & ALX_PF_ANY_REV ||
		     plats[i].pci_rev == hw->revision)) {
			if (plats[i].pflag & ALX_PF_LINK)
				hw->lnk_patch = true;
			if (plats[i].pflag & ALX_PF_HIB)
				hw->hib_patch = true;
		}
		i++;
	}
}

bool alx_get_phy_info(struct alx_hw *hw)
{
	u16  devs1, devs2;

	if (alx_read_phy_reg(hw, MII_PHYSID1, &hw->phy_id[0]) ||
	    alx_read_phy_reg(hw, MII_PHYSID2, &hw->phy_id[1]))
		return false;

	/* since we haven't PMA/PMD status2 register, we can't
	 * use mdio45_probe function for prtad and mmds.
	 * use fixed MMD3 to get mmds.
	 */
	if (alx_read_phy_ext(hw, 3, MDIO_DEVS1, &devs1) ||
	    alx_read_phy_ext(hw, 3, MDIO_DEVS2, &devs2))
		return false;
	hw->mdio.mmds = devs1 | devs2 << 16;

	return true;
}

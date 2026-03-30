// SPDX-License-Identifier: GPL-2.0-only
/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/pci.h>
#include <linux/io.h>

#include <linux/rmeda_guest.h>

static int MAX_BAR_SIZE = 0x8000000;

static int protected;
module_param(protected, int, 0660);

static int dma;
module_param(dma, int, 0660);

static int coherent;
module_param(coherent, int, 0660);

#define PCI_REALM_DEV_NAME	"pci-realm"

/*
 * Adapted from the descriptions at SMMUv3TestEngine.h. The file
 * is available as part of the FVP model package:
 * INSTALL_DIR/FastModelsPortfolio_11.25/include/components/SMMUv3TestEngine.h
 */

enum cmd {
	ENGINE_FRAME_MISCONFIGURED = ~0u - 1,
	ENGINE_ERROR  = ~0u,
	ENGINE_NO_FRAME = 0,
	ENGINE_HALTED = 1,
	ENGINE_MEMCPY = 2,
	ENGINE_RAND48 = 3,
	ENGINE_SUM64 = 4
};

struct user_frame {
	u32 cmd;
	u32 uctrl;

	u32 count_of_transactions_launched;
	u32 count_of_transactions_returned;

	u64 msiaddress;

	u32 msidata;
	u32 msiattr;

	u32 attributes;
	u32 seed;

	u64 begin;
	u64 end_incl;

	u64 stride;

	u64 udata[8];
};

struct privileged_frame {
	u32 pctrl;
	u32 downstream_port_index;

	u32 streamid;
	u32 substreamid;

	u64 pdata[14];
};

struct engine_pair {
	struct user_frame user[64 * 1024 / sizeof(struct user_frame)];
	struct privileged_frame privileged[64 * 1024 / sizeof(struct privileged_frame)];
};

struct pci_realm_dev_priv {
	struct pci_dev *dev;
	void __iomem *bar;

	struct rmeda_guest *rmeda_guest;

	int irq;
};

static irqreturn_t msi_handler(int irq, void *opaque)
{
	pr_info("Received MSI!\n");

	return IRQ_HANDLED;
}

static void test_dma(struct pci_dev *dev)
{
	struct pci_realm_dev_priv *priv = pci_get_drvdata(dev);
	struct engine_pair __iomem *pairs = priv->bar;
	u8 *source_addr = NULL, *dest_addr = NULL;
	dma_addr_t source_dma_handle, dest_dma_handle;
	struct privileged_frame *pframe;
	struct user_frame *uframe;

	source_addr = dma_alloc_coherent(&dev->dev,
					 PAGE_SIZE,
					 &source_dma_handle,
					 GFP_KERNEL);
	dest_addr = dma_alloc_coherent(&dev->dev,
				       PAGE_SIZE,
				       &dest_dma_handle,
				       GFP_KERNEL);

	if (!source_addr || !dest_addr)
		goto exit;

	pci_info(dev, "source_addr=%p, source_dma_handle=0x%llx\n",
		 source_addr, source_dma_handle);
	pci_info(dev, "dest_addr=%p, dest_dma_handle=0x%llx\n",
		 dest_addr, dest_dma_handle);

	/* Fill-in some test data */
	for (int i = 0; i < PAGE_SIZE; i++)
		source_addr[i] = i % 255;

	/* Configure DMA engine */
	pframe = &pairs->privileged[0];
	uframe = &pairs->user[0];

	/* Non-secure */
	writel_relaxed(1, &pframe->pctrl);
	/* Not used with PCI */
	writel_relaxed(0, &pframe->downstream_port_index);
	writel_relaxed(0, &pframe->streamid);
	writel_relaxed(~0, &pframe->substreamid);

	writel_relaxed(ENGINE_HALTED, &uframe->cmd);
	writel_relaxed(0, &uframe->uctrl);

	/* Configure source */
	writeq_relaxed(source_dma_handle, &uframe->begin);
	writeq_relaxed(source_dma_handle + PAGE_SIZE - 1, &uframe->end_incl);

	/*
	 * Configure attributes for source and destination:
	 * rawWB, inner shareability, non-secure
	 */
	writel_relaxed(0x42ff42ff, &uframe->attributes);
	/* Copy from start to end */
	writel_relaxed(0, &uframe->seed);

	/* Configure MSI-X */
	writeq_relaxed(1, &uframe->msiaddress);
	writel_relaxed(0, &uframe->msidata);
	writel_relaxed(0, &uframe->msiattr);

	/* Configure destination */
	writeq_relaxed(dest_dma_handle, &uframe->udata[0]);

	/* Copy everything */
	writeq_relaxed(1, &uframe->stride);

	/* Read the current number of transactions */
	unsigned int returned =
		readl_relaxed(&uframe->count_of_transactions_returned);

	/* Start memcpy */
	writel_relaxed(ENGINE_MEMCPY, &uframe->cmd);

	/* Wait for completion */
	while (readl_relaxed(&uframe->count_of_transactions_returned) ==
	       returned)
		;

	if (memcmp((void *)source_addr, (void *)dest_addr, PAGE_SIZE))
		pci_info(dev, "copy failed!\n");
	else
		pci_info(dev, "copy successful!\n");

exit:
	if (dest_addr)
		dma_free_coherent(&dev->dev,
				  PAGE_SIZE,
				  dest_addr,
				  dest_dma_handle);

	if (source_addr)
		dma_free_coherent(&dev->dev,
				  PAGE_SIZE,
				  source_addr,
				  source_dma_handle);
}

static int pci_realm_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct pci_realm_dev_priv *priv;
	struct rmeda_guest_mapping *mapping;
	unsigned int bar_id;
	size_t bar_size;
	int ret = 0;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;

	switch (dev->vendor) {
	case PCI_VENDOR_ID_NVIDIA:
		/* GPUs */
		bar_id = 2;
		if (coherent)
			bar_id = 4;
		if (dma)
			return -EINVAL;
		break;
	case PCI_VENDOR_ID_SAMSUNG:
		/* NVMes */
		MAX_BAR_SIZE = 0x2000;
		bar_id = 0;
		if (coherent || dma)
			return -EINVAL;
		break;
	case 0x13b5:
		/* SMMUv3TestEngine */
		bar_id = 0;
		if (coherent)
			return -EINVAL;
		break;
	default:
		/* Everything else */
		bar_id = 0;
		if (coherent || dma)
			return -EINVAL;
		break;
	}

	ret = pci_enable_device(dev);
	if (ret)
		goto err_enable_pci_device;

	ret = pci_request_regions(dev, PCI_REALM_DEV_NAME);
	if (ret)
		goto err_request_regions;

	/*
	 * NOTE: Restrict the BAR size if it is huge. This is done only to keep
	 * testing times reasonable when the BAR is 100s of MBs.
	 */
	bar_size = pci_resource_end(dev, bar_id) -
		   pci_resource_start(dev, bar_id) + 1;
	if (bar_size > MAX_BAR_SIZE)
		bar_size = MAX_BAR_SIZE;

	if (protected) {
		priv->rmeda_guest = rmeda_guest_start_tdisp(dev);
		if (!priv->rmeda_guest) {
			ret = -EIO;
			goto err_start_tdisp;
		}
		mapping = rmeda_guest_validate_mapping(priv->rmeda_guest,
						       pci_resource_start(dev, bar_id),
						       bar_size,
						       coherent);
		if (!mapping) {
			ret = -EIO;
			goto err_validate_mapping;
		}
	}

	priv->bar = ioremap(pci_resource_start(dev, bar_id), bar_size);
	if (!priv->bar) {
		pci_err(dev, "failed to map the bar area\n");
		ret = -ENXIO;
		goto err_map_bar;
	}

	pci_info(dev, "mapped bar as %llx\n", pci_resource_start(dev, bar_id));

	pci_set_drvdata(dev, priv);

	pci_info(dev, "bar[0]=%x\n", readl(priv->bar + 0));
	pci_info(dev, "bar[4]=%x\n", readl(priv->bar + 4));

	/* Test using the area */
	writel(0xdeadbeef, priv->bar + 20);
	pci_info(dev, "bar[4]=%x\n", readl(priv->bar + 20));

	if (!dma)
		return 0;

	/* Allow DMA */
	pci_set_master(dev);
	if (dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(64))) {
		dev_warn(&dev->dev, "No suitable DMA available\n");
		goto err_set_dma;
	}

	/* Configure IRQ */
	ret = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (ret == 0) {
		ret = -ENOMEM;
		pci_err(dev, "Failed to allocate IRQ vectors");
		goto err_alloc_irq_vectors;
	}

	priv->irq = pci_irq_vector(dev, 0);
	ret = request_irq(priv->irq, msi_handler, 0,
			  dev_name(&dev->dev), priv);
	if (ret) {
		pci_err(dev, "failed to request an irq");
		goto err_alloc_irq_handler;
	}

	pci_info(dev, "initialization done. Testing memcpy() with the engine\n");

	test_dma(dev);

	return 0;

err_alloc_irq_handler:
	pci_free_irq_vectors(dev);
err_alloc_irq_vectors:
err_set_dma:
	pci_iounmap(dev, priv->bar);
err_map_bar:
err_validate_mapping:
	if (protected)
		rmeda_guest_stop_tdisp(priv->rmeda_guest);
err_start_tdisp:
	pci_release_regions(dev);
err_request_regions:
	pci_disable_device(dev);
err_enable_pci_device:
	kfree(priv);
	pci_set_drvdata(dev, NULL);

	return ret;
}

static void pci_realm_remove(struct pci_dev *dev)
{
	struct pci_realm_dev_priv *priv = pci_get_drvdata(dev);

	if (!priv)
		return;

	if (dma) {
		free_irq(priv->irq, priv);
		pci_free_irq_vectors(dev);
	}

	pci_iounmap(dev, priv->bar);

	if (protected)
		rmeda_guest_stop_tdisp(priv->rmeda_guest);

	pci_release_regions(dev);
	pci_disable_device(dev);
	kfree(priv);
}

const struct pci_device_id realm_pci_tbl[] = {
	{ .vendor = 0xdead, .device = 0xdead, .override_only = 1 },
	{0, }
};

static struct pci_driver pci_realm_driver = {
	.name		= PCI_REALM_DEV_NAME,
	.id_table	= realm_pci_tbl,
	.probe		= pci_realm_probe,
	.remove		= pci_realm_remove,
	.driver_managed_dma = true,
};

static int __init pci_realm_init(void)
{
	int ret;

	ret = pci_register_driver(&pci_realm_driver);
	if (ret)
		return ret;

	return 0;
}
module_init(pci_realm_init);

static void __exit pci_realm_exit(void)
{
	pci_unregister_driver(&pci_realm_driver);
}
module_exit(pci_realm_exit);

MODULE_LICENSE("GPL");

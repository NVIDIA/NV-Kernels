// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2026, NVIDIA Corporation
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/iommu.h>

#define SMMUV3TESTENGINE_DEV_NAME	"smmuv3testengine"

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
	struct user_frame user[ 64 * 1024 / sizeof(struct user_frame)];
	struct privileged_frame privileged[ 64 * 1024 / sizeof(struct privileged_frame)];
};

struct smmuv3testengine_dev_priv {
	struct pci_dev *dev;
	struct engine_pair __iomem *pairs;
	int irq;
};

static irqreturn_t msi_handler(int irq, void *opaque)
{
	pr_info("Received MSI!\n");

	return IRQ_HANDLED;
}

static void test_dma(struct pci_dev *dev)
{
	struct smmuv3testengine_dev_priv *priv = pci_get_drvdata(dev);
	u8 *source_addr = NULL, *dest_addr = NULL;
	dma_addr_t source_dma_handle, dest_dma_handle;
	struct privileged_frame *pframe;
	struct user_frame *uframe;

	/* Allocate some memory */
	source_addr = dma_alloc_coherent(&dev->dev, PAGE_SIZE,
					 &source_dma_handle, GFP_KERNEL);
	if (!source_addr) {
		pci_err(dev, "failed to allocate dmable memory!");
		goto exit;
	}

	dest_addr = dma_alloc_coherent(&dev->dev, PAGE_SIZE,
				       &dest_dma_handle, GFP_KERNEL);
	if (!dest_addr) {
		pci_err(dev, "failed to allocate dmable memory!");
		goto exit;
	}

	/* Fill-in some test data */
	for (int i = 0; i < PAGE_SIZE; i++)
		source_addr[i] = i % 255;

	/* Configure DMA engine */
	pframe = &priv->pairs->privileged[0];
	uframe = &priv->pairs->user[0];

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
		returned);

	if (memcmp(source_addr, dest_addr, PAGE_SIZE))
		pci_info(dev, "Copy unsuccessful!\n");
	else
		pci_info(dev, "Copy successful!\n");

exit:
	/* Release memory */
	if (dest_addr)
		dma_free_coherent(&dev->dev, PAGE_SIZE, dest_addr, dest_dma_handle);
	if (source_addr)
		dma_free_coherent(&dev->dev, PAGE_SIZE, source_addr, source_dma_handle);
}

static int smmuv3testengine_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct smmuv3testengine_dev_priv *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = pci_enable_device(dev);
	if (ret)
		goto err_enable_pci_device;

	ret = pci_request_regions(dev, SMMUV3TESTENGINE_DEV_NAME);
	if (ret)
		goto err_request_regions;

	priv->pairs = ioremap(pci_resource_start(dev, 0),
			      pci_resource_end(dev, 0) -
			      pci_resource_start(dev, 0));

	if (!priv->pairs) {
		pci_err(dev, "failed to map the bar area\n");
		ret = -ENXIO;
		goto err_map_bar;
	}

	/* Allow DMA */
	pci_set_master(dev);
	if (dma_set_mask_and_coherent(&dev->dev, DMA_BIT_MASK(64))) {
		dev_warn(&dev->dev, "No suitable DMA available\n");
		goto err_set_dma;
	}

	/* Configure IRQ */
	ret = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (ret == 0) {
		ret = - ENOSYS;
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

	priv->dev = dev;
	pci_set_drvdata(dev, priv);

	test_dma(dev);

	return 0;

err_alloc_irq_handler:
	pci_free_irq_vectors(dev);
err_alloc_irq_vectors:
err_set_dma:
	pci_iounmap(dev, priv->pairs);
err_map_bar:
	pci_release_regions(dev);
err_request_regions:
	pci_disable_device(dev);
err_enable_pci_device:
	kfree(priv);

	return ret;
}

static void smmuv3testengine_remove(struct pci_dev *dev)
{
	struct smmuv3testengine_dev_priv *priv = pci_get_drvdata(dev);

	free_irq(priv->irq, priv);
	pci_free_irq_vectors(dev);

	pci_iounmap(dev, priv->pairs);

	pci_release_regions(dev);
	pci_disable_device(dev);

	kfree(priv);

	pci_info(dev, "unclaimed by stub\n");
}

const struct pci_device_id stub_pci_tbl[] = {
	/* Dont match to any particular pci device id and allow override */
	{ .vendor = 0xdead, .device = 0xdead, .override_only=1 },
	{0, }
};

static struct pci_driver stub_driver = {
	.name		= SMMUV3TESTENGINE_DEV_NAME,
	.id_table	= stub_pci_tbl,
	.probe		= smmuv3testengine_probe,
	.remove		= smmuv3testengine_remove,
	.driver_managed_dma = true,
};

static int __init smmuv3testengine_init(void)
{
	int ret;

	ret = pci_register_driver(&stub_driver);
	if (ret)
		return ret;

	return 0;
}

static void __exit smmuv3testengine_exit(void)
{
	pci_unregister_driver(&stub_driver);
}

module_init(smmuv3testengine_init);
module_exit(smmuv3testengine_exit);

MODULE_LICENSE("GPL");

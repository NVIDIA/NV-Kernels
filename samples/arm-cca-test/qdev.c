// SPDX-License-Identifier: GPL-2.0-only
/*
 * SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/pci.h>
#include <linux/io.h>

#include <linux/arm-smccc.h>

#define SMC_RMI_CALL(func)				\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,		\
			   ARM_SMCCC_SMC_64,		\
			   ARM_SMCCC_OWNER_STANDARD,	\
			   (func))

#define SMC_RMI_GRANULE_DELEGATE	SMC_RMI_CALL(0x0151)
#define SMC_RMI_GRANULE_UNDELEGATE	SMC_RMI_CALL(0x0152)

#define SMC_RMI_QDEV_DESTROY		SMC_RMI_CALL(0x02CE)
#define SMC_RMI_QDEV_CREATE		SMC_RMI_CALL(0x02CF)

#define RMI_QDEV_FLAGS_LINK_IDE	(1 << 0)
#define RMI_QDEV_FLAGS_C2C	(1 << 1)
#define RMI_QDEV_FLAGS_SEL_IDE	(1 << 2)

struct rmi_qdev_params {
	union {
		struct {
			unsigned long flags;
			unsigned long dev_id;
			unsigned long segment_id;
			unsigned long root_id;
			unsigned long rid_base;
			unsigned long rid_top;
		};
		u8 padding1[0x1000];
	};
};

/**
 * rmi_granule_delegate() - Delegate a granule
 * @phys: PA of the granule
 *
 * Delegate a granule for use by the realm world.
 *
 * Return: RMI return code
 */
static inline int rmi_granule_delegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_DELEGATE, phys, &res);

	return res.a0;
}

/**
 * rmi_granule_undelegate() - Undelegate a granule
 * @phys: PA of the granule
 *
 * Undelegate a granule to allow use by the normal world. Will fail if the
 * granule is in use.
 *
 * Return: RMI return code
 */
static inline int rmi_granule_undelegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_UNDELEGATE, phys, &res);

	return res.a0;
}

/**
 * rmi_qdev_create() - Setup a device in qualification mode
 * @qdev_phys: PA for QDEV descriptor structure
 * @qdev_params_phys: PA for QDEV parameters
 *
 * Return: RMI return code
 */
static inline unsigned long rmi_qdev_create(unsigned long qdev_phys,
					    unsigned long qdev_params_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_QDEV_CREATE,
			     qdev_phys, qdev_params_phys, &res);

	return res.a0;
}

/**
 * rmi_qdev_destroy() - Destroy QDEV
 * @qdev_phys: PA of the QDEV
 *
 * Return: RMI return code
 */
static inline unsigned long rmi_qdev_destroy(unsigned long qdev_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_QDEV_DESTROY, qdev_phys, &res);

	return res.a0;
}

#define QDEV_DEV_NAME	"qdev"

struct qdev_priv {
	struct pci_dev *dev;
	void *qdev;
};

static int enable_c2c;
module_param(enable_c2c, int, 0660);

static int enable_link_ide;
module_param(enable_link_ide, int, 0660);

static int enable_sel_ide;
module_param(enable_sel_ide, int, 0660);

static struct pci_dev *rdev_walk_get_pcie(struct pci_dev *epdev)
{
	struct pci_dev *pdev = epdev;
	int type;

	while ((pdev = pci_upstream_bridge(pdev))) {
		/* A sanity check */
		if (!pci_is_pcie(pdev))
			break;

		type = pci_pcie_type(pdev);

		/* Root port found? */
		if (type == PCI_EXP_TYPE_ROOT_PORT)
			return pdev;

		/* Check that the type is donwstream or upstream */
		if (type != PCI_EXP_TYPE_DOWNSTREAM &&
		    type != PCI_EXP_TYPE_UPSTREAM)
			break;
	}

	return NULL;
}

static void *qdev_enable(struct pci_dev *epdev)
{
	struct rmi_qdev_params *params;
	struct pci_dev *rpdev;
	phys_addr_t qdev_phys;
	unsigned long ret;
	void *qdev;

	rpdev = rdev_walk_get_pcie(epdev);
	if (rpdev == NULL)
		goto err_out;

	params = (struct rmi_qdev_params *)get_zeroed_page(GFP_KERNEL);
	if (!params)
		goto err_out;

	params->dev_id = pci_dev_id(epdev);
	params->rid_base = pci_dev_id(epdev);
	params->rid_top = pci_dev_id(epdev) + 1;
	params->root_id = pci_dev_id(rpdev);
	params->segment_id = pci_domain_nr(epdev->bus);
	params->flags = enable_link_ide ? RMI_QDEV_FLAGS_LINK_IDE : 0;
	params->flags |= enable_c2c ? RMI_QDEV_FLAGS_C2C : 0;
	params->flags |= enable_sel_ide ? RMI_QDEV_FLAGS_SEL_IDE : 0;

	qdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (!qdev)
		goto err_free_params;

	qdev_phys = virt_to_phys(qdev);
	if (rmi_granule_delegate(qdev_phys))
		goto err_free_qdev;

	ret = rmi_qdev_create(qdev_phys, virt_to_phys(params));
	if (ret)
		goto err_granule_undelegate;

	free_page((unsigned long)params);

	return qdev;

err_granule_undelegate:
	rmi_granule_undelegate(qdev_phys);
err_free_qdev:
	free_page((unsigned long)qdev);
err_free_params:
	free_page((unsigned long)params);
err_out:
	return NULL;
}

static void qdev_disable(void *qdev)
{
	phys_addr_t qdev_phys = virt_to_phys(qdev);
	unsigned long ret;

	ret = rmi_qdev_destroy(qdev_phys);
	if (WARN_ON(ret))
		return;

	rmi_granule_undelegate(qdev_phys);
}

static int qdev_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct qdev_priv *priv;
	int ret = 0;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;

	ret = pci_enable_device(dev);
	if (ret)
		goto err_enable_pci_device;

	priv->qdev = qdev_enable(dev);
	if (!priv->qdev) {
		ret = -ENOMEM;
		goto err_enable_qdev;
	}

	pci_set_drvdata(dev, priv);

	return 0;

err_enable_qdev:
	pci_disable_device(dev);
err_enable_pci_device:
	kfree(priv);

	return ret;
}

static void qdev_remove(struct pci_dev *dev)
{
	struct qdev_priv *priv = pci_get_drvdata(dev);

	qdev_disable(priv->qdev);

	pci_disable_device(dev);
	kfree(priv);
}

const struct pci_device_id qdev_tbl[] = {
	{ .vendor = 0xdead, .device = 0xdead, .override_only = 1 },
	{0, }
};

static struct pci_driver qdev_driver = {
	.name		= QDEV_DEV_NAME,
	.id_table	= qdev_tbl,
	.probe		= qdev_probe,
	.remove		= qdev_remove,
	.driver_managed_dma = true,
};

static int __init qdev_init(void)
{
	int ret;

	ret = pci_register_driver(&qdev_driver);
	if (ret)
		return ret;

	return 0;
}
module_init(qdev_init);

static void __exit qdev_exit(void)
{
	pci_unregister_driver(&qdev_driver);
}
module_exit(qdev_exit);

MODULE_LICENSE("GPL");

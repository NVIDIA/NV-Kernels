// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 MediaTek Inc.
 */
#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include "power_wrap.h"

/*
 *	ACPI _DSM UUID for DPM
 *	(64B66B51-38F7-3391-C689-4FA2109179AB)
 */
const guid_t pwrap_dsm_dpm_uuid = GUID_INIT(
	0x64b66b51, 0x38f7, 0x3391,
	0xc6, 0x89, 0x4f, 0xa2, 0x10, 0x91, 0x79, 0xab
);

enum mtk_pwrap_type {
	NVDA6210,
};

enum acpi_crs_mem_res {
	/* ACPI memory resource data type */
	ACPI_CRS_MEM_RES0 = 0,
	ACPI_CRS_MEM_RES1,
	ACPI_CRS_MEM_RES_NUM,
};

enum acpi_crs_irq_res {
	/* ACPI interrupt resource data type */
	ACPI_CRS_IRQ_RES0 = 0,
	ACPI_CRS_IRQ_RES1,
	ACPI_CRS_IRQ_RES_NUM,
};

static struct pwrap_dev_ctrl dev_ctrl;

/*
 * DVFSRC enable flag in SPM SYSRAM.
 *
 * The Windows PEP driver (ppmnotify.c, PepPpmLpiSupported()) writes a DVFSRC
 * enable flag into SPM SYSRAM so the firmware enables DVFSRC for the
 * suspend/resume low-power flow. On Windows the address/length/value are
 * seeded into the registry by nvpep.inx (AddReg) and read back at runtime;
 * they are fixed platform constants, so we hardcode them here.
 *
 * Windows source values (nvpep.inx):
 *   HKR,Parameters\DVFSRC,Offset,%REG_DWORD%,0x12FC00
 *   HKR,Parameters\DVFSRC,Length,%REG_DWORD%,0x4
 *   HKR,Parameters\DVFSRC,Value, %REG_DWORD%,0x1
 *
 * 0x12FC00 is an absolute physical address (not an offset into any base):
 * Windows maps it directly via MmMapIoSpaceEx(), so the Linux equivalent is
 * ioremap(0x12FC00, 4) + writel(0x1).
 */
#define PWRAP_DVFSRC_FLAG_ADDR	0x12FC00
#define PWRAP_DVFSRC_FLAG_LEN	0x4
#define PWRAP_DVFSRC_FLAG_VAL	0x1
/*
 * BestPerf performance setting register.
 *
 * A single 32-bit MMIO register that selects the SoC performance profile.
 * Writing PWRAP_BEST_PERF_VAL puts the platform into its highest-performance
 * operating point. The address/length/value are fixed platform constants, so
 * they are hardcoded here.
 *
 * ioremap(ADDR, LEN) maps the register and writel(VAL) performs one 32-bit
 * write; LEN is the size of the mapped window (4 bytes = one 32-bit register),
 * NOT the value being written.
 */
#define PWRAP_PERF_SETTING_ADDR 0x1C871E00
#define PWRAP_PERF_SETTING_LEN  0x4
#define PWRAP_BEST_PERF_VAL     0x4

/* Getter for static pwrap_dev_ctrl */
struct pwrap_dev_ctrl *pwrap_get_dev_ctrl(void)
{
	return &dev_ctrl;
}

/**
 * Query dev_config by device path.
 * Return pointer to struct pwrap_dev_config as void*, NULL otherwise.
 */
void *pwrap_query_dev_config(const char *dev_path)
{
	struct pwrap_dev_ctrl *ctrl = pwrap_get_dev_ctrl();

	if (!dev_path)
		return NULL;

	//pr_info("%s: search dev_path \"%s\"\n",
	//	__func__, dev_path);

	if (!ctrl || !ctrl->configs)
		return NULL;

	for (int i = 0; i < ctrl->count; ++i) {
		char *cfg_path = ctrl->configs[i].device_path;
		//pr_info("%s: device configs[%d] path %s\n",
		//	__func__, i, ctrl->configs[i].device_path);
		if (cfg_path && strcmp(dev_path, cfg_path) == 0)
			return (void *) &ctrl->configs[i];
	}
	return NULL;
}

/*
 * Common SCMI dispatch helper.
 * Logs the raw payload, then calls sspm_ci_set() with the provided composite
 * word as DATA_00 and the remaining three data words from the action slot.
 * Returns the sspm_ci_set() return value, or -EINVAL if control_type is not
 * CTRL_BY_SCMI.
 */
static int pwrap_scmi_dispatch(struct pwrap_dev_config *cfg,
				   u8 action_idx, u32 composite,
				   const char *action_name)
{
	if (cfg->control_type != CTRL_BY_SCMI) {
		pr_warn("%s: control type 0x%x is not scmi for dev %s\n",
			action_name, cfg->control_type, cfg->device_path);
		return -EINVAL;
	}

	pr_debug("%s: scmi payload: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
		action_name,
		cfg->scmi_config.feat_id,
		cfg->scmi_config.dev_id,
		composite,
		cfg->scmi_config.data[action_idx][SCMI_DATA_01],
		cfg->scmi_config.data[action_idx][SCMI_DATA_02],
		cfg->scmi_config.data[action_idx][SCMI_DATA_03]);

	return sspm_ci_set(cfg->scmi_config.feat_id,
			   cfg->scmi_config.dev_id,
			   composite,
			   cfg->scmi_config.data[action_idx][SCMI_DATA_01],
			   cfg->scmi_config.data[action_idx][SCMI_DATA_02],
			   cfg->scmi_config.data[action_idx][SCMI_DATA_03]);
}

int mtk_pwrap_dev_request(void *dev_cfg)
{
	struct pwrap_dev_config *cfg = (struct pwrap_dev_config *)dev_cfg;

	if (!cfg)
		return -ENODEV;
	return pwrap_scmi_dispatch(cfg, SCMI_DEV_REQUEST,
				   cfg->scmi_config.data[SCMI_DEV_REQUEST][SCMI_DATA_00],
				   __func__);
}
EXPORT_SYMBOL_GPL(mtk_pwrap_dev_request);

/**
 * mtk_send_power_control_req() - Send a client power control request to SSPM
 * @pwrctlreq: caller-allocated and -filled request descriptor
 *
 * Entry point for other drivers that need to push a power control command to
 * SSPM over the SCMI interface. The caller allocates and fills @pwrctlreq
 * (including @dev and an @InBuffer pointing to a struct power_cntl_scmi_data).
 *
 * The flow is:
 *   1. Validate @pwrctlreq and its buffers.
 *   2. Resolve @dev's ACPI full pathname and use it to look up the matching
 *      struct pwrap_dev_config (which carries the per-device scmi_config with
 *      feat_id/dev_id and the SCMI_DEV_REQUEST data words).
 *   3. Interpret @InBuffer as struct power_cntl_scmi_data.
 *   4. OR the caller's requestId/customdata into the configured request data
 *      words and issue sspm_ci_set().
 *
 * Return: 0 on success, negative errno on failure.
 */
int mtk_send_power_control_req(struct _power_cntrl_request *pwrctlreq)
{
	struct power_cntl_scmi_data *scmidata;
	struct pwrap_scmi_config *scmicfg;
	struct pwrap_dev_config *cfg;
	struct acpi_device *adev;
	struct acpi_buffer path = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status status;
	int ret;

	if (!pwrctlreq || !pwrctlreq->dev)
		return -EINVAL;

	if (!pwrctlreq->InBuffer ||
	    pwrctlreq->InBufferSize < sizeof(struct power_cntl_scmi_data)) {
		dev_err(pwrctlreq->dev, "%s: invalid input buffer\n", __func__);
		return -EINVAL;
	}

	/* Extract the ACPI companion and its full pathname from dev. */
	adev = ACPI_COMPANION(pwrctlreq->dev);
	if (!adev) {
		dev_err(pwrctlreq->dev, "%s: no ACPI companion\n", __func__);
		return -ENODEV;
	}

	status = acpi_get_name(adev->handle, ACPI_FULL_PATHNAME, &path);
	if (ACPI_FAILURE(status)) {
		dev_err(pwrctlreq->dev, "%s: failed to get ACPI path\n", __func__);
		return -EINVAL;
	}

	/* Use the ACPI path to fetch the per-device config / scmi_config. */
	cfg = pwrap_query_dev_config((char *)path.pointer);
	if (!cfg) {
		dev_err(pwrctlreq->dev, "%s: no dev config for \"%s\"\n",
			__func__, (char *)path.pointer);
		ret = -ENODEV;
		goto out;
	}

	if (cfg->control_type != CTRL_BY_SCMI) {
		dev_warn(pwrctlreq->dev, "%s: control type 0x%x is not scmi for dev %s\n",
			 __func__, cfg->control_type, cfg->device_path);
		ret = -EINVAL;
		goto out;
	}

	scmicfg = &cfg->scmi_config;

	/* Interpret the caller's input buffer as SCMI request payload data. */
	scmidata = (struct power_cntl_scmi_data *)pwrctlreq->InBuffer;

	dev_dbg(pwrctlreq->dev,
		"%s: scmi payload: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", __func__,
		scmicfg->feat_id, scmicfg->dev_id,
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_00] | scmidata->requestId,
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_01] | scmidata->customdata[SCMI_DATA_00],
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_02] | scmidata->customdata[SCMI_DATA_01],
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_03] | scmidata->customdata[SCMI_DATA_02]);

	ret = sspm_ci_set(scmicfg->feat_id, scmicfg->dev_id,
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_00] | scmidata->requestId,
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_01] | scmidata->customdata[SCMI_DATA_00],
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_02] | scmidata->customdata[SCMI_DATA_01],
		scmicfg->data[SCMI_DEV_REQUEST][SCMI_DATA_03] | scmidata->customdata[SCMI_DATA_02]);

	pwrctlreq->BytesReturned = 0;

out:
	ACPI_FREE(path.pointer);
	return ret;
}
EXPORT_SYMBOL_GPL(mtk_send_power_control_req);

int mtk_pwrap_dev_remove(void *dev_cfg)
{
	struct pwrap_dev_config *cfg = (struct pwrap_dev_config *)dev_cfg;

	if (!cfg)
		return -ENODEV;
	return pwrap_scmi_dispatch(cfg, SCMI_DEV_ADANDON,
				   cfg->scmi_config.data[SCMI_DEV_ADANDON][SCMI_DATA_00],
				   __func__);
}
EXPORT_SYMBOL_GPL(mtk_pwrap_dev_remove);

int mtk_pwrap_dev_suspend(void *dev_cfg, u8 sys_trans)
{
	struct pwrap_dev_config *cfg = (struct pwrap_dev_config *)dev_cfg;
	u32 composite;

	if (!cfg)
		return -ENODEV;
	composite = PWRAP_SCMI_DEV_ACT_PAYLOAD(
		cfg->scmi_config.data[SCMI_DEV_STATE][SCMI_DATA_00], DEV_STA_D3, 1, sys_trans);
	return pwrap_scmi_dispatch(cfg, SCMI_DEV_STATE, composite, __func__);
}
EXPORT_SYMBOL_GPL(mtk_pwrap_dev_suspend);

int mtk_pwrap_dev_resume(void *dev_cfg, u8 sys_trans)
{
	struct pwrap_dev_config *cfg = (struct pwrap_dev_config *)dev_cfg;
	u32 composite;

	if (!cfg)
		return -ENODEV;
	composite = PWRAP_SCMI_DEV_ACT_PAYLOAD(
		cfg->scmi_config.data[SCMI_DEV_STATE][SCMI_DATA_00], DEV_STA_D0, 0, sys_trans);
	return pwrap_scmi_dispatch(cfg, SCMI_DEV_STATE, composite, __func__);
}
EXPORT_SYMBOL_GPL(mtk_pwrap_dev_resume);

int mtk_pwrap_com_idle(void *dev_cfg, u8 com_idx)
{
	struct pwrap_dev_config *cfg = (struct pwrap_dev_config *)dev_cfg;
	u32 composite;

	if (!cfg)
		return -ENODEV;
	composite = PWRAP_SCMI_DEV_ACT_PAYLOAD(
		cfg->scmi_config.data[SCMI_COM_IDLE][SCMI_DATA_00], com_idx, COM_STA_L1, 1);
	return pwrap_scmi_dispatch(cfg, SCMI_COM_IDLE, composite, __func__);
}
EXPORT_SYMBOL_GPL(mtk_pwrap_com_idle);

int mtk_pwrap_com_active(void *dev_cfg, u8 com_idx)
{
	struct pwrap_dev_config *cfg = (struct pwrap_dev_config *)dev_cfg;
	u32 composite;

	if (!cfg)
		return -ENODEV;
	composite = PWRAP_SCMI_DEV_ACT_PAYLOAD(
		cfg->scmi_config.data[SCMI_COM_IDLE][SCMI_DATA_00], com_idx, COM_STA_L0, 0);
	return pwrap_scmi_dispatch(cfg, SCMI_COM_IDLE, composite, __func__);
}
EXPORT_SYMBOL_GPL(mtk_pwrap_com_active);

/**
 * Probe dev_config by ACPI path, with SCMI log if needed.
 * Return pointer to struct pwrap_dev_config as void*, NULL otherwise.
 */
void *mtk_pwrap_dev_probe(const char *acpi_path)
{
	int ret = 0;
	struct pwrap_dev_config *cfg =
		(struct pwrap_dev_config *) pwrap_query_dev_config(acpi_path);

	if (!cfg)
		return NULL;

	pr_info("%s: Device found at path %s\n", __func__, cfg->device_path);

	if (cfg->control_type == CTRL_BY_SCMI) {
		pr_info("%s: control type is scmi, payload: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
			__func__,
			cfg->scmi_config.feat_id,
			cfg->scmi_config.dev_id,
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_00],
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_01],
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_02],
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_03]);

		ret = sspm_ci_set(
			cfg->scmi_config.feat_id,
			cfg->scmi_config.dev_id,
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_00],
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_01],
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_02],
			cfg->scmi_config.data[SCMI_DEV_PROBE][SCMI_DATA_03]);

		if (ret) {
			pr_warn("%s: scmi ret = %d for device \"%s\"\n",
					__func__, ret, acpi_path);
			cfg = NULL;
		}
	}
	return (void *) cfg;
}
EXPORT_SYMBOL_GPL(mtk_pwrap_dev_probe);

static int pwrap_config_resource(struct platform_device *pdev, kernel_ulong_t driver_data)
{
	enum mtk_pwrap_type type;
	struct resource *res;
	int irq;

	if (!pdev)
		return -ENODEV;

	type = (enum mtk_pwrap_type)driver_data;
	switch (type) {
	case NVDA6210:
		res = platform_get_resource(pdev, IORESOURCE_MEM, ACPI_CRS_MEM_RES0);
		if (!res) {
			dev_err(&pdev->dev, "no memory resource for index: 0x%x\n",
				ACPI_CRS_MEM_RES0);
			return -ENOMEM;
		}
		dev_info(&pdev->dev, "ACPI MEM index 0x%x: start = 0x%llx, size = 0x%llx\n",
			 ACPI_CRS_MEM_RES0,
			 (unsigned long long)res->start,
			 (unsigned long long)resource_size(res));

		irq = platform_get_irq(pdev, ACPI_CRS_IRQ_RES0);
		if (irq < 0) {
			dev_err(&pdev->dev, "no IRQ resource for index: 0x%x, error: %d\n",
				ACPI_CRS_IRQ_RES0, irq);
			return irq;
		}
		dev_info(&pdev->dev, "ACPI IRQ index 0x%x: number = %d\n",
			 ACPI_CRS_IRQ_RES0, irq);
		break;
	default:
		dev_err(&pdev->dev, "not support memory resource for type: 0x%x\n", type);
		return -EINVAL;
	}

	return 0;
}

static int pwrap_acpi_config_init(struct device *dev)
{
	struct pwrap_dev_ctrl *ctrl = pwrap_get_dev_ctrl();
	int err;

	if (!dev)
		return -ENODEV;

	if (!ctrl)
		return -EINVAL;

	dev_info(dev, "Config dev ctrl info from ACPI data\n");

	/*
	 * Parse the full DPMT (UUID 64B66B51, func 1) into ctrl: device path,
	 * type, constraints, control_type, and - for SCMI devices - the
	 * per-device dev_id via GDSC(). Implemented in acpiutil.c.
	 */
	err = pwrap_acpi_fetch_dpm_config(dev, ctrl);
	if (err) {
		dev_err(dev, "Failed to fetch DPM config from ACPI: %d\n", err);
		memset(ctrl, 0, sizeof(struct pwrap_dev_ctrl));
	}

	return err;
}

/**
 * pwrap_probe_init_resources() - Set up drvdata, ACPI path, and device configs
 * @priv: driver private data (pdev/dev already set by caller)
 * @adev: ACPI companion device
 * @id:   matched ACPI device id (carries driver_data for resource config)
 *
 * Resolves the ACPI device path, configures the platform resources (MEM/IRQ),
 * initializes the device control config from either ACPI _DSM or the static
 * table, and then runs the initial SCMI device probe against the populated
 * config table. The device config init is non-fatal (logged as a warning);
 * ACPI path resolution and resource config failures are fatal.
 *
 * Return: 0 on success, negative errno on a fatal resource/ACPI failure.
 */
static int pwrap_probe_init_resources(struct pwrap_driver_data *priv,
					  struct acpi_device *adev,
					  const struct acpi_device_id *id)
{
	struct platform_device *pdev = priv->pdev;
	struct device *dev = priv->dev;
	acpi_status status;
	int ret;

	priv->acpi_path.length = ACPI_ALLOCATE_BUFFER;
	priv->acpi_path.pointer = NULL;
	status = acpi_get_name(adev->handle, ACPI_FULL_PATHNAME, &priv->acpi_path);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "Failed to get ACPI device path\n");
		return -EINVAL;
	}

	ret = pwrap_config_resource(pdev, id->driver_data);
	if (ret) {
		dev_err(&pdev->dev, "failed to setup resource for type: 0x%x with error: 0x%x\n",
			(enum mtk_pwrap_type)id->driver_data, ret);
		return ret;
	}

	ret = pwrap_acpi_config_init(dev);
	if (ret)
		dev_warn(&pdev->dev,
			 "Device config init failed: %d (SCMI device control disabled)\n",
			 ret);

	/*
	 * Run the initial SCMI device probe only after the device-config table
	 * has been populated by pwrap_acpi_config_init(); otherwise the lookup
	 * walks an empty table and the boot-time SCMI probe is silently skipped.
	 */
	if (!mtk_pwrap_dev_probe((char *)priv->acpi_path.pointer))
		dev_err(&pdev->dev, "Not find device config data\n");

	return 0;
}

/**
 * pwrap_write_dvfsrc_flag() - Enable DVFSRC via the SPM SYSRAM flag
 * @dev: device (used for logging)
 *
 * Writes the DVFSRC enable flag into SPM SYSRAM so the firmware enables
 * DVFSRC for the suspend/resume low-power flow. The flag address, length,
 * and value are fixed platform constants (see PWRAP_DVFSRC_FLAG_* above).
 *
 * The flag is written once at probe. This mirrors the initial write done by
 * the Windows PEP driver in PepPpmLpiSupported() (ppmnotify.c). SYSRAM
 * contents are assumed to persist across the platform sleep states used on
 * this target, so no resume-time re-write is performed.
 *
 * Failure to map the SYSRAM region is non-fatal: the driver continues so the
 * SCMI device-control path stays functional.
 */
static void pwrap_write_dvfsrc_flag(struct device *dev)
{
	void __iomem *vaddr;

	vaddr = ioremap(PWRAP_DVFSRC_FLAG_ADDR, PWRAP_DVFSRC_FLAG_LEN);
	if (!vaddr) {
		dev_warn(dev,
			 "DVFSRC: failed to map SYSRAM flag at 0x%x (DVFSRC not enabled)\n",
			 PWRAP_DVFSRC_FLAG_ADDR);
		return;
	}

	writel(PWRAP_DVFSRC_FLAG_VAL, vaddr);

	dev_info(dev,
		 "DVFSRC: enabled via SYSRAM flag phys=0x%x len=0x%x val=0x%x\n",
		 PWRAP_DVFSRC_FLAG_ADDR, PWRAP_DVFSRC_FLAG_LEN,
		 PWRAP_DVFSRC_FLAG_VAL);

	iounmap(vaddr);
}

/**
 * pwrap_write_bestperf_flag() - Select the highest SoC performance profile
 * @dev: device (used for logging)
 *
 * Writes PWRAP_BEST_PERF_VAL to the BestPerf setting register so the platform
 * comes up in its highest-performance operating point. The register address,
 * length, and value are fixed platform constants (see PWRAP_PERF_SETTING_*
 * above).
 *
 *
 * Failure to map the register is non-fatal: the driver continues so the SCMI
 * device-control path stays functional.
 */
static void pwrap_write_bestperf_flag(struct device *dev)
{
	void __iomem *vaddr;

	vaddr = ioremap(PWRAP_PERF_SETTING_ADDR, PWRAP_PERF_SETTING_LEN);
	if (!vaddr) {
		dev_warn(dev,
			 "Perf: failed to map physical address 0x%x\n",
			 PWRAP_PERF_SETTING_ADDR);
		return;
	}

	writel(PWRAP_BEST_PERF_VAL, vaddr);

	dev_info(dev,
		 "BestPerf Mode enabled via address phys=0x%x len=0x%x val=0x%x\n",
		 PWRAP_PERF_SETTING_ADDR, PWRAP_PERF_SETTING_LEN,
		 PWRAP_BEST_PERF_VAL);

	iounmap(vaddr);
}

static int mtk_pwrap_probe(struct platform_device *pdev)
{
	const struct acpi_device_id	*id;
	struct device *dev = &pdev->dev;
	struct acpi_device *adev = ACPI_COMPANION(dev);
	int ret;
	struct pwrap_driver_data *priv;

	if (!adev)
		return -ENODEV;

	id = acpi_match_device(dev->driver->acpi_match_table, dev);
	if (!id)
		return -ENODEV;

	dev_info(&pdev->dev, "device probe for \"%s\"\n", id->id);

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	platform_set_drvdata(pdev, priv);
	priv->pdev = pdev;
	priv->dev = dev;

	/* Resolve ACPI path, configure resources, init device configs */
	ret = pwrap_probe_init_resources(priv, adev, id);
	if (ret)
		return ret;

	/*
	 * Enable DVFSRC by writing the SPM SYSRAM flag. Ported from the
	 * Windows PEP driver (PepPpmLpiSupported() in ppmnotify.c). Non-fatal.
	 */
	pwrap_write_dvfsrc_flag(dev);

	/*
	 * Set performace mode to BestPerf setting by default on driver probe
	 */
	pwrap_write_bestperf_flag(dev);

	/*
	 * The sysfs nodes are debug/test hooks. Their creation must not fail
	 * probe or disable the driver, so log a warning and continue if the
	 * attribute group could not be added.
	 */
	ret = pwrap_create_sys_files(pdev);
	if (ret)
		dev_warn(&pdev->dev,
			 "failed to create sysfs nodes: %d (continuing)\n", ret);

	return 0;
}

static void mtk_pwrap_remove(struct platform_device *pdev)
{
	struct pwrap_driver_data *priv = platform_get_drvdata(pdev);

	if (priv) {
		/*
		 * The dev_ctrl configs[] array and its device_path/
		 * device_type strings are heap-allocated by
		 * pwrap_acpi_fetch_dpm_config(); free them here.
		 */
		pwrap_acpi_dpm_config_free(pwrap_get_dev_ctrl());

		ACPI_FREE(priv->acpi_path.pointer);
	}
}

#ifdef CONFIG_ACPI
static const struct acpi_device_id mtk_pwrap_acpi_ids[] = {
	{ .id = "NVDA6210", .driver_data = NVDA6210 },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(acpi, mtk_pwrap_acpi_ids);
#endif /* CONFIG_ACPI */

static struct platform_driver mtk_pwrap_driver = {
	.driver = {
		.name = "mtk_pwrap",
#ifdef CONFIG_ACPI
		.acpi_match_table = mtk_pwrap_acpi_ids,
#endif /* CONFIG_ACPI */
		/*
		 * mtk_pwrap_dev_probe() hands consumers raw pointers into the
		 * dev_ctrl configs[] table that remove() frees. Suppress the
		 * sysfs bind/unbind attributes so userspace cannot unbind the
		 * driver (freeing that table) while a consumer still holds a
		 * pointer into it.
		 */
		.suppress_bind_attrs = true,
	},
	.probe = mtk_pwrap_probe,
	.remove = mtk_pwrap_remove,
};

static int __init power_wrap_init(void)
{
	int ret = 0;

	ret = platform_driver_register(&mtk_pwrap_driver);

	pr_info("%s driver register: %d\n", __func__, ret);

	return ret;
}

/*
 * This driver is built-in (obj-y) and bound for the lifetime of the system;
 * it provides no module_exit()/remove path beyond the platform .remove above.
 */
subsys_initcall(power_wrap_init);
MODULE_LICENSE("GPL");


/*
 * While CLOSid/RMID can be attributed to a task, task mode is not supported as
 * tasks have already been labelled by resctrl.
 */
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/resctrl.h>

struct resctrl_pmu {
	struct pmu pmu;
	struct device *dev;
};

#define to_resctrl_pmu(p) (container_of(p, struct resctrl_pmu, pmu))

#define RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(_name, _config, _start, _end)        \
	static inline u64 get_##_name(struct perf_event *event)            \
	{                                                                  \
		return FIELD_GET(GENMASK_ULL(_end, _start),                \
				 event->attr._config);                     \
	}                                                                  \

RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(event, config, 0, 7);
RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(domain, config, 16, 23);
RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(resctrl_id, config1, 0, 63);

static void resctrl_pmu_do_nothing(struct pmu *pmu)
{
}

static bool resctrl_event_supported(u16 event_num)
{
	enum resctrl_event_id event_id = event_num;

	switch (event_id) {
	case QOS_L3_OCCUP_EVENT_ID:
		/*
		 * L3 occupancy is state, changes in the counter don't
		 * represent an event. The counter can go down as well
		 * as up!
		 */
		return false;
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		return resctrl_arch_is_mbm_total_enabled();
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		return resctrl_arch_is_mbm_local_enabled();
	}

	return false;
}

static struct rdt_resource *resctrl_event_get_resource(u16 event_num)
{
	enum resctrl_event_id event_id = event_num;

	switch (event_id) {
	case QOS_L3_OCCUP_EVENT_ID:
	case QOS_L3_MBM_TOTAL_EVENT_ID:
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		return resctrl_arch_get_resource(RDT_RESOURCE_L3);
	}

	return NULL;
}

static void resctrl_pmu_event_destroy(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u16 event_num = get_event(event);
	struct rdt_resource *r;

	r = resctrl_event_get_resource(event_num);
	if (!r)
		return;

	resctrl_arch_mon_ctx_free(r, event_num, hwc->idx);
}

static int resctrl_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct resctrl_pmu *resctrl_pmu = to_resctrl_pmu(event->pmu);
	struct device *dev = resctrl_pmu->dev;
	struct perf_event *sibling;
	struct rdt_resource *r;
	struct rdt_domain *d;
	u16 event_num, domain_id;
	u32 closid, rmid;
	int err;
	u64 id;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (is_sampling_event(event) || event->attach_state & PERF_ATTACH_TASK)
		return -EOPNOTSUPP;

	if (event->cpu < 0) {
		dev_dbg(dev, "Per-task mode not supported\n");
		return -EOPNOTSUPP;
	}

	/* Verify specified event is supported on this PMU */
	event_num = get_event(event);
	if (!resctrl_event_supported(event_num)) {
		dev_dbg(dev, "Invalid event %d for this PMU\n", event_num);
		return -EINVAL;
	}

	/* Verify the resctrl group currently exists */
	id = get_resctrl_id(event);
	err = resctrl_id_decode(id, &closid, &rmid);
	if (err)
		return err;

	/* Sanity check we have a resource and domain for this event */
	r = resctrl_event_get_resource(event_num);
	if (!r)
		return -EINVAL;

	domain_id = get_domain(event);
	cpus_read_lock();
	d = resctrl_arch_find_domain(r, domain_id);
	if (!d || WARN_ON_ONCE(cpumask_empty(&d->cpu_mask))) {
		cpus_read_unlock();
		return -EINVAL;
	}

	/* This must run on one of the domain's CPUs */
	event->cpu = cpumask_any(&d->cpu_mask);
	cpus_read_unlock();

	if (!is_software_event(event->group_leader)) {
		if (event->group_leader->pmu != event->pmu)
			return -EINVAL;
	}

	/* Don't allow groups with other PMUs, except for s/w events */
	for_each_sibling_event(sibling, event->group_leader) {
		if (is_software_event(sibling))
			continue;
		if (sibling->pmu != event->pmu)
			return -EINVAL;
	}

	hwc->idx = resctrl_arch_mon_ctx_alloc_no_wait(r, event_num);
	if (hwc->idx == -ENOSPC)
		return -ENOSPC;
	event->destroy = resctrl_pmu_event_destroy;
	local64_set(&hwc->prev_count, 0);
	local64_set(&event->count, 0);

	return err;
}

static void resctrl_pmu_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 delta, now, prev, id;
	u16 event_num, domain_id;
	struct rdt_resource *r;
	struct rdt_domain *d;
	u32 closid, rmid;
	int err;

	event_num = get_event(event);
	id = get_resctrl_id(event);
	__resctrl_id_decode(id, &closid, &rmid);

	r = resctrl_event_get_resource(event_num);
	if (!r)
		return;
	domain_id = get_domain(event);
	d = resctrl_arch_find_domain(r, domain_id);
	if (!d)
		return;

	if (!cpumask_test_cpu(smp_processor_id(), &d->cpu_mask))
		return;

	do {
		prev = local64_read(&hwc->prev_count);

		err = resctrl_arch_rmid_read(r, d, closid, rmid,
					     event_num, &now, hwc->idx);
		if (err)
			return;
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	/*
	 * Discard the first reading to initialise prev_count.
	 * Resctrl already handled overflow.
	 */
	if (prev != 0) {
		delta = now - prev;
		local64_add(delta, &event->count);
	}

	set_bit(PERF_HES_UPTODATE, (long *)&hwc->state);
}

static void resctrl_pmu_event_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	/* Update prev_count, to make start the 0 point */
	if (!test_bit(PERF_HES_UPTODATE, (long *)&hwc->state))
		resctrl_pmu_event_update(event);
}

static void resctrl_pmu_event_stop(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_UPDATE)
		resctrl_pmu_event_update(event);
}

static int resctrl_pmu_event_add(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_START)
		resctrl_pmu_event_start(event, flags);
	perf_event_update_userpage(event);

	return 0;
}

static void resctrl_pmu_event_del(struct perf_event *event, int flags)
{
	resctrl_pmu_event_stop(event, flags | PERF_EF_UPDATE);
	perf_event_update_userpage(event);
}

/*
 * Not all architetures do anything with resctrl_arch_mon_ctx_alloc_no_wait(),
 * so hwc->idx may be meaningless.
 */
static int resctrl_pmu_event_idx(struct perf_event *event)
{
	u16 event_num = get_event(event);
	u64 id = get_resctrl_id(event);
	u32 closid, rmid, idx;

	__resctrl_id_decode(id, &closid, &rmid);
	idx = resctrl_arch_rmid_idx_encode(closid, rmid);

	return idx << ilog2(RESCTRL_MAX_EVENT_NUM) | event_num;
}

/* Events */
static ssize_t resctrl_pmu_show(struct device *dev,
				struct device_attribute *attr, char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);

	return sysfs_emit(page, "event=0x%llx\n", pmu_attr->id);
}

/*
 * IDs must match enum resctrl_event_id, and names must match the name used by
 * resctrl.
 */
static struct attribute *resctrl_pmu_events[] = {
	PMU_EVENT_ATTR_ID(mbm_total_bytes, resctrl_pmu_show, QOS_L3_MBM_TOTAL_EVENT_ID),
	PMU_EVENT_ATTR_ID(mbm_local_bytes, resctrl_pmu_show, QOS_L3_MBM_LOCAL_EVENT_ID),
	NULL
};

static umode_t resctrl_pmu_event_is_visible(struct kobject *kobj,
					    struct attribute *attr, int unused)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr.attr);
	if (resctrl_event_supported(pmu_attr->id))
		return attr->mode;

	return 0;
}

static const struct attribute_group resctrl_pmu_events_group = {
	.name = "events",
	.attrs = resctrl_pmu_events,
	.is_visible = resctrl_pmu_event_is_visible,
};

/* Formats */
PMU_FORMAT_ATTR(event,       "config:0-7");
PMU_FORMAT_ATTR(domain,      "config:16-23");
PMU_FORMAT_ATTR(resctrl_id,  "config1:0-63");

static struct attribute *resctrl_pmu_formats[] = {
	&format_attr_event.attr,
	&format_attr_domain.attr,
	&format_attr_resctrl_id.attr,
	NULL
};

static const struct attribute_group resctrl_pmu_format_group = {
	.name = "format",
	.attrs = resctrl_pmu_formats,
};

/* cpumask */
static ssize_t resctrl_pmu_cpumask_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	/*
	 * PMU events only need opening on one CPU, as resctrl already
	 * counts system-wide. The event must be handled on the CPU that
	 * handles the overflow interrupt, as there isn't one, this CPU
	 * will do.
	 */
	return sprintf(buf, "%u\n", raw_smp_processor_id());
}

static struct device_attribute resctrl_pmu_cpumask_attr =
		__ATTR(cpumask, 0444, resctrl_pmu_cpumask_show, NULL);

static struct attribute *resctrl_pmu_cpumask_attrs[] = {
	&resctrl_pmu_cpumask_attr.attr,
	NULL
};

static const struct attribute_group resctrl_pmu_cpumask_group = {
	.attrs = resctrl_pmu_cpumask_attrs,
};

static const struct attribute_group *resctrl_pmu_attr_grps[] = {
	&resctrl_pmu_events_group,
	&resctrl_pmu_format_group,
	&resctrl_pmu_cpumask_group,
	NULL
};

static int resctrl_pmu_probe(struct platform_device *pdev)
{
	struct resctrl_pmu *resctrl_pmu;
	struct device *dev = &pdev->dev;
	int err;

	resctrl_pmu = devm_kzalloc(dev, sizeof(*resctrl_pmu), GFP_KERNEL);
	if (!resctrl_pmu)
		return -ENOMEM;

	resctrl_pmu->dev = dev;
	platform_set_drvdata(pdev, resctrl_pmu);

	resctrl_pmu->pmu = (struct pmu) {
		.module		= THIS_MODULE,
		.task_ctx_nr    = perf_invalid_context,
		.pmu_enable	= resctrl_pmu_do_nothing,
		.pmu_disable	= resctrl_pmu_do_nothing,
		.event_init	= resctrl_pmu_event_init,
		.event_idx	= resctrl_pmu_event_idx,
		.add		= resctrl_pmu_event_add,
		.del		= resctrl_pmu_event_del,
		.start		= resctrl_pmu_event_start,
		.stop		= resctrl_pmu_event_stop,
		.read		= resctrl_pmu_event_update,

		.attr_groups	= resctrl_pmu_attr_grps,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	};

	err = perf_pmu_register(&resctrl_pmu->pmu, "resctrl_pmu", -1);
	if (err) {
		dev_err(dev, "Error %d registering PMU\n", err);
		return err;
	}

	return 0;
}

static int resctrl_pmu_remove(struct platform_device *pdev)
{
	struct resctrl_pmu *resctrl_pmu = platform_get_drvdata(pdev);

	perf_pmu_unregister(&resctrl_pmu->pmu);

	return 0;
}

static struct platform_driver resctrl_pmu_driver = {
	.driver = {
		.name = "resctrl_pmu",
	},
	.probe = resctrl_pmu_probe,
	.remove = resctrl_pmu_remove,
};
module_platform_driver(resctrl_pmu_driver);

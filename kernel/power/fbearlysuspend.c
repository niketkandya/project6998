/* kernel/power/fbearlysuspend.c
 *
 * Copyright (C) 2005-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/dev_namespace.h>
#include <linux/earlysuspend.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "power.h"

#define MAX_BUF 100

static int display = 1;
enum fb_state_e {
	FB_STATE_STOPPED_DRAWING,
	FB_STATE_REQUEST_STOP_DRAWING,
	FB_STATE_DRAWING_OK,
};

struct fbes_dev_ns {
	spinlock_t         fb_state_lock;
	wait_queue_head_t  fb_state_wq;
	enum fb_state_e    fb_state;

	struct dev_ns_info dev_ns_info;
};

static void fbes_ns_initialize(struct dev_namespace *dev_ns,
			       struct fbes_dev_ns *fbes_ns);

#ifdef CONFIG_DEV_NS
/*
 * init_fbes_ns, get_fbes_ns(),
 * get_fbes_ns_cur(), put_fbes_ns()
 * is_active_fbes_ns(), get_fbes_nb_self()
 */
DEFINE_DEV_NS_INFO(fbes)

static struct dev_ns_info *fbes_ns_create(struct dev_namespace *dev_ns)
{
	struct fbes_dev_ns *fbes_ns;

	fbes_ns = kzalloc(sizeof(*fbes_ns), GFP_KERNEL);
	if (!fbes_ns)
		return ERR_PTR(-ENOMEM);

	fbes_ns_initialize(dev_ns, fbes_ns);

	return &fbes_ns->dev_ns_info;
}

static void fbes_ns_release(struct dev_ns_info *dev_ns_info)
{
	struct fbes_dev_ns *fbes_ns;

	fbes_ns = container_of(dev_ns_info, struct fbes_dev_ns, dev_ns_info);
	dev_ns_unregister_notify(dev_ns_info->dev_ns, &dev_ns_info->nb);
	kfree(fbes_ns);
}

static int fbes_ns_switch_callback(struct notifier_block *self,
				   unsigned long action, void *data)
{
	unsigned long irqflags;
	struct fbes_dev_ns *fbes_ns;
	struct dev_namespace *dev_ns = data;
	int ret = 0;

	fbes_ns = get_fbes_nb_self(self);

	spin_lock_irqsave(&fbes_ns->fb_state_lock, irqflags);
	switch (action) {
	case DEV_NS_EVENT_ACTIVATE:
		fbes_ns->fb_state = FB_STATE_DRAWING_OK;
		pr_info("fbearlysuspend: activating '%s:0x%p' "
			"(DRAWING_OK)\n", dev_ns->tag, dev_ns);
		break;
	case DEV_NS_EVENT_DEACTIVATE:
		fbes_ns->fb_state = FB_STATE_REQUEST_STOP_DRAWING;
		pr_info("fbearlysuspend: de-activating '%s:0x%p' "
			"(STOP_DRAWING)\n", dev_ns->tag, dev_ns);
		break;
	default:
		break;
	}
	spin_unlock_irqrestore(&fbes_ns->fb_state_lock, irqflags);

	wake_up_all(&fbes_ns->fb_state_wq);

	return ret;
}

static struct dev_ns_ops fbes_ns_ops = {
	.create = fbes_ns_create,
	.release = fbes_ns_release,
};

static struct notifier_block fbes_ns_switch_notifier = {
	.notifier_call = fbes_ns_switch_callback,
};

#else
/*
 * init_fbes_ns, get_fbes_ns(),
 * get_fbes_ns_cur(), put_fbes_ns()
 * is_active_fbes_ns(), get_fbes_nb_self()
 */
DEFINE_DEV_NS_INIT(fbes)
#endif

static void fbes_ns_initialize(struct dev_namespace *dev_ns,
			       struct fbes_dev_ns *fbes_ns)
{
	fbes_ns->fb_state_lock = __SPIN_LOCK_UNLOCKED(fbes_ns->fb_state_lock);
	fbes_ns->fb_state = is_active_dev_ns(dev_ns) ? FB_STATE_DRAWING_OK
				: FB_STATE_REQUEST_STOP_DRAWING;
	init_waitqueue_head(&fbes_ns->fb_state_wq);

	fbes_ns->dev_ns_info.dev_ns = dev_ns;
#ifdef CONFIG_DEV_NS
	fbes_ns->dev_ns_info.nb = fbes_ns_switch_notifier;
	dev_ns_register_notify(dev_ns, &fbes_ns->dev_ns_info.nb);
#endif
}

static inline struct fbes_dev_ns *set_fbes_state(struct fbes_dev_ns *fbes_ns,
						 enum fb_state_e new_state)
{
	unsigned long irq_flags;
	struct fbes_dev_ns *active_fbes_ns;

	if (fbes_ns->dev_ns_info.dev_ns == &init_dev_ns) {
		/* from the init ns also wake up the active namespace */
		active_fbes_ns = find_fbes_ns(&init_dev_ns);
		if (active_fbes_ns) {
			spin_lock_irqsave(&fbes_ns->fb_state_lock, irq_flags);
			active_fbes_ns->fb_state = new_state;
			spin_unlock_irqrestore(&fbes_ns->fb_state_lock, irq_flags);
			wake_up_all(&active_fbes_ns->fb_state_wq);
		}
	}

	spin_lock_irqsave(&fbes_ns->fb_state_lock, irq_flags);
	fbes_ns->fb_state = new_state;
	spin_unlock_irqrestore(&fbes_ns->fb_state_lock, irq_flags);

	wake_up_all(&fbes_ns->fb_state_wq);

	return fbes_ns;
}

/* tell userspace to stop drawing, wait for it to stop */
static void stop_drawing_early_suspend(struct early_suspend *h)
{
	int ret;
	struct fbes_dev_ns *fbes_ns;

	fbes_ns = get_fbes_ns_cur();
	BUG_ON(!fbes_ns);

	fbes_ns = set_fbes_state(fbes_ns, FB_STATE_REQUEST_STOP_DRAWING);

	ret = wait_event_timeout(fbes_ns->fb_state_wq,
				 fbes_ns->fb_state == FB_STATE_STOPPED_DRAWING,
				 HZ);
	if (unlikely(fbes_ns->fb_state != FB_STATE_STOPPED_DRAWING))
		pr_warning("stop_drawing_early_suspend: timeout waiting for "
			   "userspace to stop drawing\n");

	put_fbes_ns(fbes_ns);

#ifdef CONFIG_PM_DEBUG
	pr_info("%sed\n", __func__);
#endif
}

/* tell userspace to start drawing */
static void start_drawing_late_resume(struct early_suspend *h)
{
	struct fbes_dev_ns *fbes_ns;

	fbes_ns = get_fbes_ns_cur();
	BUG_ON(!fbes_ns);

	fbes_ns = set_fbes_state(fbes_ns, FB_STATE_DRAWING_OK);

	put_fbes_ns(fbes_ns);
#ifdef CONFIG_PM_DEBUG
	pr_info("%sd\n", __func__);
#endif
}

static struct early_suspend stop_drawing_early_suspend_desc = {
	.level = EARLY_SUSPEND_LEVEL_STOP_DRAWING,
	.suspend = stop_drawing_early_suspend,
	.resume = start_drawing_late_resume,
};

static ssize_t wait_for_fb_sleep_show(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	char *s = buf;
	int ret;
	struct fbes_dev_ns *fbes_ns = get_fbes_ns_cur();

#ifdef CONFIG_DEV_NS
	unsigned long irqflags;

	/*
	 * if a namespace starts as inactive, and a process opens the
	 * fbearlysuspend sysfs file before any namespace notification
	 * can occur, then we want to make sure we sync the fbes_ns state.
	 */
	spin_lock_irqsave(&fbes_ns->fb_state_lock, irqflags);
	if (!is_active_fbes_dev_ns(fbes_ns)) {
		pr_info("wait_for_fb_sleep: "
			"inactive dev_ns:'%s' forced to sleep!\n",
			fbes_ns->dev_ns_info.dev_ns->tag);
		fbes_ns->fb_state = FB_STATE_REQUEST_STOP_DRAWING;
		wake_up_all(&fbes_ns->fb_state_wq);
	}
	spin_unlock_irqrestore(&fbes_ns->fb_state_lock, irqflags);
#endif

	ret = wait_event_interruptible(fbes_ns->fb_state_wq,
				       fbes_ns->fb_state != FB_STATE_DRAWING_OK);
	if (ret && fbes_ns->fb_state == FB_STATE_DRAWING_OK)
		goto out;
	s += sprintf(buf, "sleeping");
	ret = s - buf;
out:
	put_fbes_ns(fbes_ns);
	return ret;
}

static ssize_t wait_for_fb_wake_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	char *s = buf;
	int ret;
	unsigned long irq_flags;
	struct fbes_dev_ns *fbes_ns = get_fbes_ns_cur();

	spin_lock_irqsave(&fbes_ns->fb_state_lock, irq_flags);
#ifdef CONFIG_DEV_NS
	if (!is_active_fbes_dev_ns(fbes_ns)) {
		pr_info("wait_for_wake: "
			"inactive dev_ns:'%s' forced to sleep!\n",
			fbes_ns->dev_ns_info.dev_ns->tag);
		fbes_ns->fb_state = FB_STATE_REQUEST_STOP_DRAWING;
	}
#endif
	if (fbes_ns->fb_state == FB_STATE_REQUEST_STOP_DRAWING) {
		fbes_ns->fb_state = FB_STATE_STOPPED_DRAWING;
		wake_up_all(&fbes_ns->fb_state_wq);
	}
	spin_unlock_irqrestore(&fbes_ns->fb_state_lock, irq_flags);

	ret = wait_event_interruptible(fbes_ns->fb_state_wq,
				       fbes_ns->fb_state == FB_STATE_DRAWING_OK);
	if (ret && fbes_ns->fb_state != FB_STATE_DRAWING_OK)
		goto out;
	s += sprintf(buf, "awake");
	ret = s - buf;
out:
	put_fbes_ns(fbes_ns);
	return ret;
}

static ssize_t wait_for_fb_status_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	int ret = 0;

	if (display == 1)
		ret = snprintf(buf, strnlen("on", MAX_BUF) + 1, "on");
	else
		ret = snprintf(buf, strnlen("off", MAX_BUF) + 1, "off");

	return ret;
}

#define power_ro_attr(_name) \
static struct kobj_attribute _name##_attr = {	\
	.attr	= {				\
		.name = __stringify(_name),	\
		.mode = 0444,			\
	},					\
	.show	= _name##_show,			\
	.store	= NULL,		\
}

power_ro_attr(wait_for_fb_sleep);
power_ro_attr(wait_for_fb_wake);
power_ro_attr(wait_for_fb_status);

static struct attribute *g[] = {
	&wait_for_fb_sleep_attr.attr,
	&wait_for_fb_wake_attr.attr,
	&wait_for_fb_status_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = g,
};

static int __init android_power_init(void)
{
	int ret;

#ifdef CONFIG_DEV_NS
	ret = DEV_NS_REGISTER(fbes, "fbes");
	if (ret < 0)
		return ret;
#else
	fbes_ns_initialize(&init_dev_ns, &init_fbes_ns);
#endif
	ret = sysfs_create_group(power_kobj, &attr_group);
	if (ret) {
		pr_err("android_power_init: sysfs_create_group failed\n");
		return ret;
	}

	register_early_suspend(&stop_drawing_early_suspend_desc);
	return 0;
}

static void  __exit android_power_exit(void)
{
#ifdef CONFIG_DEV_NS
	DEV_NS_UNREGISTER(fbes);
#endif
	unregister_early_suspend(&stop_drawing_early_suspend_desc);
	sysfs_remove_group(power_kobj, &attr_group);
}

module_init(android_power_init);
module_exit(android_power_exit);


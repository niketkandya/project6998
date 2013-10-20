/* kernel/power/earlysuspend.c
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

#include <linux/earlysuspend.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rtc.h>
#include <linux/syscalls.h> /* sys_sync */
#include <linux/wakelock.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/dev_namespace.h>

#include "power.h"

enum {
	DEBUG_USER_STATE = 1U << 0,
	DEBUG_SUSPEND = 1U << 2,
	DEBUG_VERBOSE = 1U << 3,
};

#ifdef CONFIG_PM_DEBUG
/* debug callbacks registered with early_suspend and late_resume rotuines */
static int debug_mask = DEBUG_USER_STATE | DEBUG_SUSPEND;
#else
static int debug_mask = DEBUG_USER_STATE;
#endif

module_param_named(debug_mask, debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP);

static DEFINE_MUTEX(early_suspend_lock);
static LIST_HEAD(early_suspend_handlers);
static void early_suspend(struct work_struct *work);
static void late_resume(struct work_struct *work);
static DECLARE_WORK(early_suspend_work, early_suspend);
static DECLARE_WORK(late_resume_work, late_resume);
static DEFINE_SPINLOCK(state_lock);
enum {
	SUSPEND_REQUESTED = 0x1,
	SUSPENDED = 0x2,
	SUSPEND_REQUESTED_AND_SUSPENDED = SUSPEND_REQUESTED | SUSPENDED,
};

static int g_state;
suspend_state_t requested_suspend_state = PM_SUSPEND_MEM;

struct earlysuspend_dev_ns {
	int state;
	suspend_state_t suspend_state;

	struct dev_ns_info dev_ns_info;
};

static void earlysuspend_ns_initialize(struct dev_namespace *dev_ns,
				       struct earlysuspend_dev_ns *es_ns);

static void do_request_suspend_state(suspend_state_t new_state,
				     struct earlysuspend_dev_ns *es_ns);

#ifdef CONFIG_DEV_NS
/*
 * init_earlysuspend_ns, get_earlysuspend_ns(),
 * get_earlysuspend_ns_cur(), put_earlysuspend_ns()
 * is_active_earlysuspend_ns(), get_earlysuspend_nb_self()
 */
DEFINE_DEV_NS_INFO(earlysuspend)

static struct dev_ns_info *earlysuspend_ns_create(struct dev_namespace *dev_ns)
{
	struct earlysuspend_dev_ns *es_ns;

	es_ns = kzalloc(sizeof(*es_ns), GFP_KERNEL);
	if (!es_ns)
		return ERR_PTR(-ENOMEM);
	earlysuspend_ns_initialize(dev_ns, es_ns);
	return &es_ns->dev_ns_info;
}

static void earlysuspend_ns_release(struct dev_ns_info *dev_ns_info)
{
	struct earlysuspend_dev_ns *es_ns;

	es_ns = container_of(dev_ns_info,
			     struct earlysuspend_dev_ns, dev_ns_info);
	dev_ns_unregister_notify(dev_ns_info->dev_ns, &dev_ns_info->nb);
	kfree(es_ns);
}

static int earlysuspend_ns_switch_callback(struct notifier_block *self,
					   unsigned long action, void *data)
{
	struct earlysuspend_dev_ns *es_ns;

	es_ns = get_earlysuspend_nb_self(self);

	switch (action) {
	case DEV_NS_EVENT_ACTIVATE:
		/* ensure that the new namespace is ON and active */
		pr_info("earlysuspend: activate '%s'",
			es_ns->dev_ns_info.dev_ns->tag);
		do_request_suspend_state(PM_SUSPEND_ON, es_ns);
		break;
	case DEV_NS_EVENT_DEACTIVATE:
		pr_info("earlysuspend: deactivate '%s'",
			es_ns->dev_ns_info.dev_ns->tag);
		do_request_suspend_state(PM_SUSPEND_MEM, es_ns);
		break;
	default:
		break;
	}

	return 0;
}

static struct dev_ns_ops earlysuspend_ns_ops = {
	.create = earlysuspend_ns_create,
	.release = earlysuspend_ns_release,
};

static struct notifier_block earlysuspend_ns_switch_notifier = {
	.notifier_call = earlysuspend_ns_switch_callback,
};

#else
/*
 * init_earlysuspend_ns, get_earlysuspend_ns(),
 * get_earlysuspend_ns_cur(), put_earlysuspend_ns()
 * is_active_earlysuspend_ns(), get_earlysuspend_nb_self()
 */
DEFINE_DEV_NS_INIT(earlysuspend)
#endif

static void earlysuspend_ns_initialize(struct dev_namespace *dev_ns,
				       struct earlysuspend_dev_ns *es_ns)
{
	es_ns->state = 0;
	es_ns->suspend_state = PM_SUSPEND_MEM;
#ifdef CONFIG_DEV_NS
	es_ns->dev_ns_info.nb = earlysuspend_ns_switch_notifier;
	dev_ns_register_notify(dev_ns, &es_ns->dev_ns_info.nb);
#endif
}

void register_early_suspend(struct early_suspend *handler)
{
	struct list_head *pos;

	mutex_lock(&early_suspend_lock);
	list_for_each(pos, &early_suspend_handlers) {
		struct early_suspend *e;
		e = list_entry(pos, struct early_suspend, link);
		if (e->level > handler->level)
			break;
	}
	list_add_tail(&handler->link, pos);
	if ((g_state & SUSPENDED) && handler->suspend)
		handler->suspend(handler);
	mutex_unlock(&early_suspend_lock);
}
EXPORT_SYMBOL(register_early_suspend);

void unregister_early_suspend(struct early_suspend *handler)
{
	mutex_lock(&early_suspend_lock);
	list_del(&handler->link);
	mutex_unlock(&early_suspend_lock);
}
EXPORT_SYMBOL(unregister_early_suspend);

static void early_suspend(struct work_struct *work)
{
	struct early_suspend *pos;
	unsigned long irqflags;
	struct earlysuspend_dev_ns *es_ns;
	struct dev_namespace *dev_ns;
	int abort = 0;

	es_ns = get_earlysuspend_ns_cur();
	BUG_ON(!es_ns);
	dev_ns = es_ns->dev_ns_info.dev_ns;

	mutex_lock(&early_suspend_lock);
	spin_lock_irqsave(&state_lock, irqflags);

	if (es_ns->state == SUSPEND_REQUESTED) {
		es_ns->state |= SUSPENDED;
		if (is_active_dev_ns(dev_ns) || dev_ns == &init_dev_ns) {
			g_state = SUSPEND_REQUESTED;
			requested_suspend_state = es_ns->suspend_state;
		}
	}

	if (g_state == SUSPEND_REQUESTED)
		g_state |= SUSPENDED;
	else
		abort = 1;
	spin_unlock_irqrestore(&state_lock, irqflags);

	if (abort) {
		if (debug_mask & DEBUG_SUSPEND)
			pr_info("early_suspend(%s): abort\n", dev_ns->tag);
		mutex_unlock(&early_suspend_lock);
		goto abort;
	}

	if (debug_mask & DEBUG_SUSPEND)
		pr_info("early_suspend(%s): call handlers\n", dev_ns->tag);
	list_for_each_entry(pos, &early_suspend_handlers, link) {
		if (pos->suspend != NULL) {
			if (debug_mask & DEBUG_VERBOSE)
				pr_info("early_suspend(%s): calling %pf\n",
					dev_ns->tag, pos->suspend);
			pos->suspend(pos);
		}
	}
	mutex_unlock(&early_suspend_lock);

	suspend_sys_sync_queue();
abort:
	spin_lock_irqsave(&state_lock, irqflags);
	if (g_state == SUSPEND_REQUESTED_AND_SUSPENDED ||
	    (is_active_dev_ns(dev_ns) &&
	     es_ns->state == SUSPEND_REQUESTED_AND_SUSPENDED))
		wake_unlock(&main_wake_lock);
	spin_unlock_irqrestore(&state_lock, irqflags);

	put_earlysuspend_ns(es_ns);
}

static void late_resume(struct work_struct *work)
{
	struct early_suspend *pos;
	unsigned long irqflags;
	struct earlysuspend_dev_ns *es_ns;
	struct dev_namespace *dev_ns;
	int abort = 0;

	es_ns = get_earlysuspend_ns_cur();
	BUG_ON(!es_ns);
	dev_ns = es_ns->dev_ns_info.dev_ns;

	mutex_lock(&early_suspend_lock);
	spin_lock_irqsave(&state_lock, irqflags);
	if (es_ns->state == SUSPENDED) {
		es_ns->state &= ~SUSPENDED;
		if (is_active_dev_ns(dev_ns) || dev_ns == &init_dev_ns) {
			g_state = SUSPENDED;
			requested_suspend_state = es_ns->suspend_state;
		}
	}

	if (g_state == SUSPENDED)
		g_state &= ~SUSPENDED;
	else
		abort = 1;
	spin_unlock_irqrestore(&state_lock, irqflags);

	if (abort) {
		if (debug_mask & DEBUG_SUSPEND)
			pr_info("late_resume(%s): abort\n", dev_ns->tag);
		goto abort;
	}
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("late_resume(%s): call handlers\n", dev_ns->tag);
	list_for_each_entry_reverse(pos, &early_suspend_handlers, link) {
		if (pos->resume != NULL) {
			if (debug_mask & DEBUG_VERBOSE)
				pr_info("late_resume(%s): calling %pf\n",
					dev_ns->tag, pos->resume);

			pos->resume(pos);
		}
	}
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("late_resume(%s): done\n", dev_ns->tag);
abort:
	mutex_unlock(&early_suspend_lock);
	put_earlysuspend_ns(es_ns);
}

static void do_request_suspend_state(suspend_state_t new_state,
				     struct earlysuspend_dev_ns *es_ns)
{
	unsigned long irqflags;
	int old_sleep;
	struct dev_namespace *dev_ns = es_ns->dev_ns_info.dev_ns;
	struct nsproxy *nsp;
	bool set_globals = false;

	nsp = dev_ns_nsproxy(dev_ns);

	if (is_active_dev_ns(dev_ns) || dev_ns == &init_dev_ns)
		set_globals = true;

	spin_lock_irqsave(&state_lock, irqflags);
	old_sleep = es_ns->state & SUSPEND_REQUESTED;
	if (debug_mask & DEBUG_USER_STATE) {
		struct timespec ts;
		struct rtc_time tm;
		getnstimeofday(&ts);
		rtc_time_to_tm(ts.tv_sec, &tm);
		pr_info("request_suspend_state(%s): %s (%d/%d->%d) at %lld "
			"(%d-%02d-%02d %02d:%02d:%02d.%09lu UTC)\n",
			dev_ns->tag,
			new_state != PM_SUSPEND_ON ? "sleep" : "wakeup",
			requested_suspend_state, es_ns->suspend_state, new_state,
			ktime_to_ns(ktime_get()),
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
	}
maybe_queue_work:
	if (!old_sleep && new_state != PM_SUSPEND_ON) {
		es_ns->state |= SUSPEND_REQUESTED;
		queue_work_in(nsp, suspend_work_queue, &early_suspend_work);
	} else if (old_sleep && new_state == PM_SUSPEND_ON) {
		es_ns->state &= ~SUSPEND_REQUESTED;
		wake_lock(&main_wake_lock);
		queue_work_in(nsp, suspend_work_queue, &late_resume_work);
	} else if (set_globals) {
		old_sleep = g_state & SUSPEND_REQUESTED;
		g_state = es_ns->state;
		requested_suspend_state = new_state;
		set_globals = false;
		if (!old_sleep && new_state != PM_SUSPEND_ON)
			g_state |= SUSPEND_REQUESTED;
		else if (old_sleep && new_state == PM_SUSPEND_ON)
			g_state &= !SUSPEND_REQUESTED;
		goto maybe_queue_work;
	}

	es_ns->suspend_state = new_state;

	spin_unlock_irqrestore(&state_lock, irqflags);
}

void request_suspend_state(suspend_state_t new_state)
{
	struct earlysuspend_dev_ns *es_ns;

	es_ns = get_earlysuspend_ns_cur();
	BUG_ON(!es_ns);

	do_request_suspend_state(new_state, es_ns);

	put_earlysuspend_ns(es_ns);
}

suspend_state_t get_suspend_state(void)
{
	struct earlysuspend_dev_ns *es_ns;
	suspend_state_t s;

	es_ns = get_earlysuspend_ns_cur();
	s = es_ns->suspend_state;
	put_earlysuspend_ns(es_ns);

	return s;
}

static int __init earlysuspend_init(void)
{
	int ret;

#ifdef CONFIG_DEV_NS
	ret = DEV_NS_REGISTER(earlysuspend, "earlysuspend");
	if (ret < 0)
		return ret;
#else
	earlysuspend_ns_initialize(&init_dev_ns, &init_earlysuspend_ns);
#endif
	return ret;
}

static void __exit earlysuspend_exit(void)
{
	DEV_NS_UNREGISTER(earlysuspend);
}

core_initcall(earlysuspend_init);
module_exit(earlysuspend_exit);

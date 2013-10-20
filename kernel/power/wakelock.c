/* kernel/power/wakelock.c
 *
 * Copyright (C) 2005-2008 Google, Inc.
 *
 * Device namespace support by:
 *   Jeremy C. Andrus <jeremya@cs.columbia.edu>
 *   Namespace virtualization of wakelocks and early suspend follows the
 *   paradigm described in the "Cells" paper:
 *       http://systems.cs.columbia.edu/files/wpid-cells-sosp2011.pdf
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

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/rtc.h>
#include <linux/suspend.h>
#include <linux/syscalls.h> /* sys_sync */
#include <linux/wakelock.h>
#include <linux/workqueue.h>
#include <linux/dev_namespace.h>
#include <linux/slab.h>
#ifdef CONFIG_WAKELOCK_STAT
#include <linux/proc_fs.h>
#endif
#include "power.h"

struct wl_ns_token {
#ifdef CONFIG_DEV_NS
	atomic_t count;
	struct dev_namespace *ns;
	long timeout;
	long flags;
	struct list_head link;
#endif
};

enum {
	DEBUG_EXIT_SUSPEND = 1U << 0,
	DEBUG_WAKEUP = 1U << 1,
	DEBUG_SUSPEND = 1U << 2,
	DEBUG_EXPIRE = 1U << 3,
	DEBUG_WAKE_LOCK = 1U << 4,
};

#ifdef CONFIG_PM_DEBUG
/* debug status of active wakelock held and when entering PM transition */
static int debug_mask = DEBUG_EXIT_SUSPEND | DEBUG_WAKEUP | DEBUG_SUSPEND;
#else
static int debug_mask = DEBUG_EXIT_SUSPEND | DEBUG_WAKEUP;
#endif

module_param_named(debug_mask, debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP);

#define WAKE_LOCK_TYPE_MASK              (0x0f)
#define WAKE_LOCK_INITIALIZED            (1U << 8)
#define WAKE_LOCK_ACTIVE                 (1U << 9)
#define WAKE_LOCK_AUTO_EXPIRE            (1U << 10)
#define WAKE_LOCK_PREVENTING_SUSPEND     (1U << 11)

static DEFINE_SPINLOCK(list_lock);
static LIST_HEAD(inactive_locks);
static struct list_head active_wake_locks[WAKE_LOCK_TYPE_COUNT];
static int current_event_num;
static int suspend_sys_sync_count;
static DEFINE_SPINLOCK(suspend_sys_sync_lock);
static struct workqueue_struct *suspend_sys_sync_work_queue;
static DECLARE_COMPLETION(suspend_sys_sync_comp);
struct workqueue_struct *suspend_work_queue;
struct wake_lock main_wake_lock;
static struct wake_lock unknown_wakeup;
static struct wake_lock suspend_backoff_lock;

#define SUSPEND_BACKOFF_THRESHOLD	10
#define SUSPEND_BACKOFF_INTERVAL	10000

static unsigned suspend_short_count;

/* adjust the timer value based on passed in timeout */
static inline void wake_lock_adjust_timer(struct wake_lock *lock,
					  struct dev_namespace *ns,
					  long timeout,
					  int has_timeout);

static void wake_lock_internal(struct wake_lock *lock,
			       struct dev_namespace *ns,
			       long timeout, int has_timeout);

#ifdef CONFIG_DEV_NS
/*
 * this will be true when the caller is either a kernel thread,
 * or interrupt context (or actually in the init context)
 */
static inline int is_init_ns(struct dev_namespace *ns)
{
	if (ns == &init_dev_ns)
		return 1;
	return 0;
}

static inline int is_active_token(struct wl_ns_token *token)
{
	if (!token || !token->ns)
		return 1;
	return is_init_ns(token->ns) || is_active_dev_ns(token->ns);
}

static int __wake_locked_in(struct wake_lock *lock,
			    struct dev_namespace *ns,
			    struct wl_ns_token **token)
{
	int ret = 1;
	struct wl_ns_token *t = NULL;

	if (lock && (lock->flags & WAKE_LOCK_ACTIVE)) {
		if (is_init_ns(ns))
			goto found_one;

		/*
		 * *) If the lock is active, but doesn't have any tokens, then
		 *    it was locked by the kernel somewhere, call it locked in
		 *    current ns as well
		 * *) If the lock is active and locked by the init_dev_ns then
		 *    also call it locked in the current ns
		 *    (trust kernel/drivers + assume all locking was correct)
		 */
		if (list_empty(&lock->locked_by))
			goto found_one;
		list_for_each_entry(t, &lock->locked_by, link) {
			if (t->ns == ns || is_init_ns(t->ns))
				goto found_one;
		}
	}
	t = NULL;
	ret = 0;

found_one:
	if (token)
		*token = t;
	return ret;
}

/*
 * Cache recently used wake lock tokens to avoid lots
 * of GFP_ATOMIC kmalloc calls. Serialized by 'list_lock'.
 */
static LIST_HEAD(recent_tokens);
static int nr_recent_tokens;
#define MAX_RECENT_TOKENS 10

/* caller must hold 'list_lock' */
static inline struct wl_ns_token *
get_ns_token(struct wake_lock *lock, struct dev_namespace *ns)
{
	struct wl_ns_token *token;

	if (is_init_ns(ns))
		return NULL;

	list_for_each_entry(token, &lock->locked_by, link) {
		if (token->ns == ns)
			return token;
	}

	if (!list_empty(&recent_tokens)) {
		/* use cache of recently used tokens (avoid atomic kmalloc) */
		token = list_first_entry(&recent_tokens,
					 struct wl_ns_token, link);
		list_del_init(&token->link);
		--nr_recent_tokens;
	} else {
		token = kzalloc(sizeof(*token), GFP_ATOMIC);
	}

	if (!token)
		return NULL;

	token->ns = ns;
	token->timeout = 0;
	token->flags = lock->flags;
	list_add(&token->link, &lock->locked_by);
	return token;
}

static inline void drop_ns_token(struct wl_ns_token *token)
{
	if (!token)
		return;

	BUG_ON(list_empty(&token->link));

	list_del_init(&token->link);

	if (nr_recent_tokens < MAX_RECENT_TOKENS) {
		list_add_tail(&token->link, &recent_tokens);
		++nr_recent_tokens;
	} else {
		kfree(token);
	}
}

static inline void drop_all_ns_tokens(struct wake_lock *lock)
{
	struct wl_ns_token *token, *n;

	list_for_each_entry_safe(token, n, &lock->locked_by, link)
		drop_ns_token(token);

	INIT_LIST_HEAD(&lock->locked_by);
}

static inline void __adjust_lock_ns(struct dev_namespace *ns,
				    struct wake_lock *lock,
				    struct wl_ns_token *token,
				    struct wake_lock **max_lock,
				    unsigned long *max_timeout)
{
	if (!token)
		return;

	lock->flags = token->flags;
	if (!token->timeout)
		return;

	lock->expires = jiffies + token->timeout;
	pr_info("         |-> adjusted %s timeout:%ld,"
		"expires:%ld\n", lock->name,
		token->timeout, lock->expires);
	if (token->timeout > *max_timeout) {
		*max_timeout = token->timeout;
		*max_lock = lock;
	}
}

static inline void __adjust_all_locks_ns(struct dev_namespace *ns)
{
	unsigned long irqflags;
	int type, ret;
	struct wake_lock *lock, *max_lock = NULL;
	struct wl_ns_token *token = NULL;
	unsigned long max_timeout = 0;

	spin_lock_irqsave(&list_lock, irqflags);
	for (type = 0; type < WAKE_LOCK_TYPE_COUNT; type++) {
		pr_info("         (%s) looking for locks of type %d...\n",
			ns->tag, type);
		list_for_each_entry(lock, &active_wake_locks[type], link) {
			ret = __wake_locked_in(lock, ns, &token);
			if (ret)
				__adjust_lock_ns(ns, lock, token,
						 &max_lock, &max_timeout);
		}
	}
	if (max_lock)
		wake_lock_adjust_timer(max_lock, ns, max_timeout,
				       (max_timeout > 0));
	spin_unlock_irqrestore(&list_lock, irqflags);
}

static int wake_lock_ns_switch_callback(struct notifier_block *self,
					unsigned long action, void *data)
{
	struct dev_namespace *ns = (struct dev_namespace *)data;

	switch (action) {
	case DEV_NS_EVENT_ACTIVATE:
		pr_info("wakelocks(%s): activating...\n", ns->tag);
		/*
		 * run through the list of active locks and re-adjust
		 * timeouts based on values set in the namespace which
		 * is now becoming active
		 */
		__adjust_all_locks_ns(ns);
		pr_info("         (%s): activate COMPLETE.\n", ns->tag);
		break;
	case DEV_NS_EVENT_DEACTIVATE:
		/* nothing to do yet... */
		break;
	default:
		break;
	}

	return 0;
}

static struct notifier_block wake_lock_ns_switch_notifier = {
	.notifier_call = wake_lock_ns_switch_callback,
};

#else /* !CONFIG_DEV_NS */

static inline int is_init_ns(struct dev_namespace *ns)
{
	return 1;
}

static inline int is_active_token(struct wl_ns_token *token)
{
	return 1;
}

static int __wake_locked_in(struct wake_lock *lock,
			    struct dev_namespace *ns,
			    struct wl_ns_token **token)
{
	int ret = 0;
	if (lock && lock->flags & WAKE_LOCK_ACTIVE)
		ret = 1;
	if (token)
		*token = NULL;
	return ret;
}

static inline struct wl_ns_token *
get_ns_token(struct wake_lock *lock, struct dev_namespace *ns)
{
	return NULL;
}

#define drop_ns_token(x)
#define drop_all_ns_tokens(x)

#endif /* !CONFIG_DEV_NS */

int wake_locked_in(struct wake_lock *lock, struct dev_namespace *ns)
{
	unsigned long irqflags;
	int ret;
	spin_lock_irqsave(&list_lock, irqflags);
	ret = __wake_locked_in(lock, ns, NULL);
	spin_unlock_irqrestore(&list_lock, irqflags);
	return ret;
}
EXPORT_SYMBOL(wake_locked_in);

#ifdef CONFIG_WAKELOCK_STAT
static struct wake_lock deleted_wake_locks;
static ktime_t last_sleep_time_update;
static int wait_for_wakeup;

int get_expired_time(struct wake_lock *lock, ktime_t *expire_time)
{
	struct timespec ts;
	struct timespec kt;
	struct timespec tomono;
	struct timespec delta;
	struct timespec sleep;
	long timeout;

	if (!(lock->flags & WAKE_LOCK_AUTO_EXPIRE))
		return 0;
	get_xtime_and_monotonic_and_sleep_offset(&kt, &tomono, &sleep);
	timeout = lock->expires - jiffies;
	if (timeout > 0)
		return 0;
	jiffies_to_timespec(-timeout, &delta);
	set_normalized_timespec(&ts, kt.tv_sec + tomono.tv_sec - delta.tv_sec,
				kt.tv_nsec + tomono.tv_nsec - delta.tv_nsec);
	*expire_time = timespec_to_ktime(ts);
	return 1;
}


static int print_lock_stat(struct seq_file *m, struct wake_lock *lock)
{
	int lock_count = lock->stat.count;
	int expire_count = lock->stat.expire_count;
	ktime_t active_time = ktime_set(0, 0);
	ktime_t total_time = lock->stat.total_time;
	ktime_t max_time = lock->stat.max_time;
	char *ns_list = "";
#ifdef CONFIG_DEV_NS
	struct wl_ns_token *token;
	char ns_str[128];
	int pos;
#endif

	ktime_t prevent_suspend_time = lock->stat.prevent_suspend_time;
	if (lock->flags & WAKE_LOCK_ACTIVE) {
		ktime_t now, add_time;
		int expired = get_expired_time(lock, &now);
		if (!expired)
			now = ktime_get();
		add_time = ktime_sub(now, lock->stat.last_time);
		lock_count++;
		if (!expired)
			active_time = add_time;
		else
			expire_count++;
		total_time = ktime_add(total_time, add_time);
		if (lock->flags & WAKE_LOCK_PREVENTING_SUSPEND)
			prevent_suspend_time = ktime_add(prevent_suspend_time,
					ktime_sub(now, last_sleep_time_update));
		if (add_time.tv64 > max_time.tv64)
			max_time = add_time;
#ifdef CONFIG_DEV_NS
		strncpy(ns_str, "(KERNEL):0:0", sizeof(ns_str));
		pos = 0;
		list_for_each_entry(token, &lock->locked_by, link) {
			if (pos >= sizeof(ns_str))
				break;
			pos += snprintf(ns_str + pos, sizeof(ns_str) - pos,
					"(%s):%ld",
					token->ns ? token->ns->tag : "-none-",
					token->timeout);
		}
		ns_list = &ns_str[0];
#endif
	}

	return seq_printf(m, "\"%34s\" \"%40s\" %14d %14d %14d %14lld "
			  "%14lld %14lld %14lld %14lld\n",
			  lock->name, ns_list, lock_count, expire_count,
			  lock->stat.wakeup_count,
			  ktime_to_ns(active_time),
			  ktime_to_ns(total_time),
			  ktime_to_ns(prevent_suspend_time),
			  ktime_to_ns(max_time),
			  ktime_to_ns(lock->stat.last_time));
}

static int wakelock_stats_show(struct seq_file *m, void *unused)
{
	unsigned long irqflags;
	struct wake_lock *lock;
	int ret;
	int type;

	ret = seq_printf(m, "%36s %42s %14s %14s %14s "
			 "%14s %14s %14s "
			 "%14s %14s\n",
			 "name", "ns","count","expire_count","wake_count",
			 "active_since","total_time","sleep_time",
			 "max_time","last_change");
	spin_lock_irqsave(&list_lock, irqflags);

	ret = seq_puts(m, "name\tcount\texpire_count\twake_count\tactive_since"
			"\ttotal_time\tsleep_time\tmax_time\tlast_change\n");
	list_for_each_entry(lock, &inactive_locks, link)
		ret = print_lock_stat(m, lock);
	for (type = 0; type < WAKE_LOCK_TYPE_COUNT; type++) {
		seq_printf(m, "---------- %26s Locks ----------\n",
			   type == WAKE_LOCK_SUSPEND ? "SUSPEND" :
			    (type == WAKE_LOCK_IDLE ? "IDLE" : "<unknown>"));
		list_for_each_entry(lock, &active_wake_locks[type], link)
			ret = print_lock_stat(m, lock);
	}
	spin_unlock_irqrestore(&list_lock, irqflags);
	return 0;
}

static void wake_unlock_stat_locked(struct wake_lock *lock, int expired)
{
	ktime_t duration;
	ktime_t now;
	if (!(lock->flags & WAKE_LOCK_ACTIVE))
		return;
	if (get_expired_time(lock, &now))
		expired = 1;
	else
		now = ktime_get();
	lock->stat.count++;
	if (expired)
		lock->stat.expire_count++;
	duration = ktime_sub(now, lock->stat.last_time);
	lock->stat.total_time = ktime_add(lock->stat.total_time, duration);
	if (ktime_to_ns(duration) > ktime_to_ns(lock->stat.max_time))
		lock->stat.max_time = duration;
	lock->stat.last_time = ktime_get();
	if (lock->flags & WAKE_LOCK_PREVENTING_SUSPEND) {
		duration = ktime_sub(now, last_sleep_time_update);
		lock->stat.prevent_suspend_time = ktime_add(
			lock->stat.prevent_suspend_time, duration);
		lock->flags &= ~WAKE_LOCK_PREVENTING_SUSPEND;
	}
}

static void update_sleep_wait_stats_locked(int done)
{
	struct wake_lock *lock;
	ktime_t now, etime, elapsed, add;
	int expired;

	now = ktime_get();
	elapsed = ktime_sub(now, last_sleep_time_update);
	list_for_each_entry(lock, &active_wake_locks[WAKE_LOCK_SUSPEND], link) {
		expired = get_expired_time(lock, &etime);
		if (lock->flags & WAKE_LOCK_PREVENTING_SUSPEND) {
			if (expired)
				add = ktime_sub(etime, last_sleep_time_update);
			else
				add = elapsed;
			lock->stat.prevent_suspend_time = ktime_add(
				lock->stat.prevent_suspend_time, add);
		}
		if (done || expired)
			lock->flags &= ~WAKE_LOCK_PREVENTING_SUSPEND;
		else
			lock->flags |= WAKE_LOCK_PREVENTING_SUSPEND;
	}
	last_sleep_time_update = now;
}
#else /* CONFIG_WAKELOCK_STAT */
static int wakelock_stats_show(struct seq_file *m, void *unused)
{
	int ret;

	ret = seq_puts(m, "name\tns\tcount\texpire_count\twake_count\tactive_since"
			"\ttotal_time\tsleep_time\tmax_time\tlast_change\n");
	seq_puts(m, "NO STATS\n\n");
	return 0;
}
#endif


static void expire_wake_lock(struct wake_lock *lock, struct wl_ns_token *token)
{
#ifdef CONFIG_WAKELOCK_STAT
	wake_unlock_stat_locked(lock, 1);
#endif

	/*
	 * drop our token to the wake lock, but don't actually expire if
	 * another namespace has a handle... unless we're called from
	 * the init context (e.g. an interrupt handler)
	 */
	drop_ns_token(token);
	if (!is_init_ns(current_dev_ns()) && !list_empty(&lock->locked_by)) {
		if (debug_mask & (DEBUG_WAKE_LOCK | DEBUG_EXPIRE))
			pr_info("%s expired in %s, but locked in another NS\n",
				lock->name, current_dev_ns()->tag);
		return;
	}

	lock->flags &= ~(WAKE_LOCK_ACTIVE | WAKE_LOCK_AUTO_EXPIRE);
	list_del(&lock->link);
	list_add(&lock->link, &inactive_locks);
	if (debug_mask & (DEBUG_WAKE_LOCK | DEBUG_EXPIRE))
		pr_info("expired wake lock %s\n", lock->name);
}

/* Caller must acquire the list_lock spinlock */
static void print_active_locks(int type)
{
	struct wake_lock *lock;
	bool print_expired = true;
	char *lis = "";
#ifdef CONFIG_DEV_NS
	struct wl_ns_token *token;
	char li_str[128];
	int pos;
	li_str[0] = '\0';
#endif

	if (!list_empty(&active_wake_locks[type]))
		pr_info("Active Wake Locks of type %d:\n", type);
	BUG_ON(type >= WAKE_LOCK_TYPE_COUNT);
	list_for_each_entry(lock, &active_wake_locks[type], link) {
#ifdef CONFIG_DEV_NS
		pos = 0;
		pos += snprintf(li_str + pos, sizeof(li_str) - pos,
				", locked-in: ");
		list_for_each_entry(token, &lock->locked_by, link) {
			if (pos >= sizeof(li_str))
				break;
			pos += snprintf(li_str + pos, sizeof(li_str) - pos,
					"(%s):%ld;",
					token->ns ? token->ns->tag : "-none-",
					token->timeout);
		}
		lis = li_str;
#endif
		if (lock->flags & WAKE_LOCK_AUTO_EXPIRE) {
			long timeout = lock->expires - jiffies;
			if (timeout > 0)
				pr_info("active wake lock %s, time left %ld\n",
					lock->name, timeout);
			else if (print_expired)
				pr_info("wake lock %s, expired\n", lock->name);
		} else {
			pr_info("active wake lock %s\n", lock->name);
			if (!(debug_mask & DEBUG_EXPIRE))
				print_expired = false;
		}
	}
}

static long has_wake_lock_locked_in(int type, struct dev_namespace *ns)
{
	struct wake_lock *lock, *n;
	long max_timeout = 0;
	int ret;
	struct wl_ns_token *token = NULL;

	BUG_ON(type >= WAKE_LOCK_TYPE_COUNT);

	/* inactive containers always "have a lock" */
	if (!is_init_ns(ns) && !is_active_dev_ns(ns))
		return -1;

	list_for_each_entry_safe(lock, n, &active_wake_locks[type], link) {
		ret = __wake_locked_in(lock, ns, &token);
		if (!ret)
			continue;
		if (lock->flags & WAKE_LOCK_AUTO_EXPIRE) {
			long timeout = lock->expires - jiffies;
			if (timeout <= 0)
				expire_wake_lock(lock, token);
			else if (timeout > max_timeout)
				max_timeout = timeout;
		} else
			return -1;
	}
	return max_timeout;
}

static long has_wake_lock_locked(int type)
{
	return has_wake_lock_locked_in(type, current_dev_ns());
}

long has_wake_lock(int type)
{
	long ret;
	unsigned long irqflags;
	spin_lock_irqsave(&list_lock, irqflags);
	ret = has_wake_lock_locked(type);
	if (ret && (debug_mask & DEBUG_WAKEUP) && type == WAKE_LOCK_SUSPEND)
		print_active_locks(type);
	spin_unlock_irqrestore(&list_lock, irqflags);
	return ret;
}

static void suspend_sys_sync(struct work_struct *work)
{
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("PM: Syncing filesystems...\n");

	sys_sync();

	if (debug_mask & DEBUG_SUSPEND)
		pr_info("sync done.\n");

	spin_lock(&suspend_sys_sync_lock);
	suspend_sys_sync_count--;
	spin_unlock(&suspend_sys_sync_lock);
}
static DECLARE_WORK(suspend_sys_sync_work, suspend_sys_sync);

void suspend_sys_sync_queue(void)
{
	int ret;

	spin_lock(&suspend_sys_sync_lock);
	ret = queue_work(suspend_sys_sync_work_queue, &suspend_sys_sync_work);
	if (ret)
		suspend_sys_sync_count++;
	spin_unlock(&suspend_sys_sync_lock);
}

static bool suspend_sys_sync_abort;
static void suspend_sys_sync_handler(unsigned long);
static DEFINE_TIMER(suspend_sys_sync_timer, suspend_sys_sync_handler, 0, 0);
/* value should be less then half of input event wake lock timeout value
 * which is currently set to 5*HZ (see drivers/input/evdev.c)
 */
#define SUSPEND_SYS_SYNC_TIMEOUT (HZ/4)
static void suspend_sys_sync_handler(unsigned long arg)
{
	if (suspend_sys_sync_count == 0) {
		complete(&suspend_sys_sync_comp);
	} else if (has_wake_lock(WAKE_LOCK_SUSPEND)) {
		suspend_sys_sync_abort = true;
		complete(&suspend_sys_sync_comp);
	} else {
		mod_timer(&suspend_sys_sync_timer, jiffies +
				SUSPEND_SYS_SYNC_TIMEOUT);
	}
}

int suspend_sys_sync_wait(void)
{
	suspend_sys_sync_abort = false;

	if (suspend_sys_sync_count != 0) {
		mod_timer(&suspend_sys_sync_timer, jiffies +
				SUSPEND_SYS_SYNC_TIMEOUT);
		wait_for_completion(&suspend_sys_sync_comp);
	}
	if (suspend_sys_sync_abort) {
		pr_info("suspend aborted....while waiting for sys_sync\n");
		return -EAGAIN;
	}

	return 0;
}

static void suspend_backoff(void)
{
	pr_info("suspend: too many immediate wakeups, back off\n");
	wake_lock_timeout(&suspend_backoff_lock,
			  msecs_to_jiffies(SUSPEND_BACKOFF_INTERVAL));
}

static void suspend(struct work_struct *work)
{
	int ret;
	int entry_event_num;
	struct timespec ts_entry, ts_exit;

	pr_info("suspend(%s) from wake unlock\n", current_dev_ns()->tag);

	if (has_wake_lock(WAKE_LOCK_SUSPEND)) {
		if (debug_mask & DEBUG_SUSPEND)
			pr_info("suspend: abort suspend\n");
		return;
	}

	entry_event_num = current_event_num;
	suspend_sys_sync_queue();
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("suspend: enter suspend\n");
	getnstimeofday(&ts_entry);
	ret = pm_suspend(get_suspend_state());
	getnstimeofday(&ts_exit);

	if (debug_mask & DEBUG_EXIT_SUSPEND) {
		struct rtc_time tm;
		rtc_time_to_tm(ts_exit.tv_sec, &tm);
		pr_info("suspend: exit suspend, ret = %d "
			"(%d-%02d-%02d %02d:%02d:%02d.%09lu UTC)\n", ret,
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec, ts_exit.tv_nsec);
	}

	if (ts_exit.tv_sec - ts_entry.tv_sec <= 1) {
		++suspend_short_count;

		if (suspend_short_count == SUSPEND_BACKOFF_THRESHOLD) {
			suspend_backoff();
			suspend_short_count = 0;
		}
	} else {
		suspend_short_count = 0;
	}

	if (!ret && current_event_num == entry_event_num) {
		if (debug_mask & DEBUG_SUSPEND)
			pr_info("suspend: pm_suspend returned with no event\n");
		wake_lock_timeout(&unknown_wakeup, HZ / 2);
	}
}
static DECLARE_WORK(suspend_work, suspend);

static void expire_wake_locks(unsigned long data)
{
	long has_lock;
	unsigned long irqflags;
	struct nsproxy *nsp = (struct nsproxy *)data;
	struct dev_namespace *ns = (nsp ? nsp->dev_ns : &init_dev_ns);

	if (debug_mask & DEBUG_SUSPEND)
		pr_info("expire_wake_locks: start [%s]\n", ns->tag);
	spin_lock_irqsave(&list_lock, irqflags);
	if (debug_mask & DEBUG_SUSPEND)
		print_active_locks(WAKE_LOCK_SUSPEND);
	has_lock = has_wake_lock_locked_in(WAKE_LOCK_SUSPEND, ns);
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("expire_wake_locks: done. %s\n",
			has_lock ? "Has Lock(s)" : "NO locks");
	if (has_lock == 0)
		queue_work_in(nsp, suspend_work_queue, &suspend_work);
	spin_unlock_irqrestore(&list_lock, irqflags);
}
static DEFINE_TIMER(expire_timer, expire_wake_locks, 0, 0);

static int power_suspend_late(struct device *dev)
{
	int ret = has_wake_lock(WAKE_LOCK_SUSPEND) ? -EAGAIN : 0;
#ifdef CONFIG_WAKELOCK_STAT
	wait_for_wakeup = !ret;
#endif
	if (debug_mask & DEBUG_SUSPEND)
		pr_info("power_suspend_late return %d\n", ret);
	return ret;
}

static struct dev_pm_ops power_driver_pm_ops = {
	.suspend_noirq = power_suspend_late,
};

static struct platform_driver power_driver = {
	.driver.name = "power",
	.driver.pm = &power_driver_pm_ops,
};
static struct platform_device power_device = {
	.name = "power",
};

void wake_lock_init(struct wake_lock *lock, int type, const char *name)
{
	unsigned long irqflags = 0;

	if (name)
		lock->name = name;
	BUG_ON(!lock->name);

	if (debug_mask & DEBUG_WAKE_LOCK)
		pr_info("wake_lock_init name=%s\n", lock->name);
#ifdef CONFIG_WAKELOCK_STAT
	lock->stat.count = 0;
	lock->stat.expire_count = 0;
	lock->stat.wakeup_count = 0;
	lock->stat.total_time = ktime_set(0, 0);
	lock->stat.prevent_suspend_time = ktime_set(0, 0);
	lock->stat.max_time = ktime_set(0, 0);
	lock->stat.last_time = ktime_set(0, 0);
#endif
	lock->flags = (type & WAKE_LOCK_TYPE_MASK) | WAKE_LOCK_INITIALIZED;

	INIT_LIST_HEAD(&lock->link);
	INIT_LIST_HEAD(&lock->locked_by);
	spin_lock_irqsave(&list_lock, irqflags);
	list_add(&lock->link, &inactive_locks);
	spin_unlock_irqrestore(&list_lock, irqflags);
}
EXPORT_SYMBOL(wake_lock_init);

void wake_lock_destroy(struct wake_lock *lock)
{
	unsigned long irqflags;
	if (debug_mask & DEBUG_WAKE_LOCK)
		pr_info("wake_lock_destroy(%s) name=%s\n",
			current_dev_ns()->tag, lock->name);
	spin_lock_irqsave(&list_lock, irqflags);
	lock->flags &= ~WAKE_LOCK_INITIALIZED;
#ifdef CONFIG_WAKELOCK_STAT
	if (lock->stat.count) {
		deleted_wake_locks.stat.count += lock->stat.count;
		deleted_wake_locks.stat.expire_count += lock->stat.expire_count;
		deleted_wake_locks.stat.total_time =
			ktime_add(deleted_wake_locks.stat.total_time,
				  lock->stat.total_time);
		deleted_wake_locks.stat.prevent_suspend_time =
			ktime_add(deleted_wake_locks.stat.prevent_suspend_time,
				  lock->stat.prevent_suspend_time);
		deleted_wake_locks.stat.max_time =
			ktime_add(deleted_wake_locks.stat.max_time,
				  lock->stat.max_time);
	}
#endif
	list_del(&lock->link);
	drop_all_ns_tokens(lock);
	spin_unlock_irqrestore(&list_lock, irqflags);
}
EXPORT_SYMBOL(wake_lock_destroy);

static void wake_lock_internal(struct wake_lock *lock,
			       struct dev_namespace *ns,
			       long timeout, int has_timeout)
{
	int type;
	unsigned long irqflags;
	int should_mod_lock = 1;
	struct wl_ns_token *token;

	spin_lock_irqsave(&list_lock, irqflags);
	type = lock->flags & WAKE_LOCK_TYPE_MASK;

	BUG_ON(type >= WAKE_LOCK_TYPE_COUNT);
	BUG_ON(!(lock->flags & WAKE_LOCK_INITIALIZED));
#ifdef CONFIG_WAKELOCK_STAT
	if (type == WAKE_LOCK_SUSPEND && wait_for_wakeup) {
		if (debug_mask & DEBUG_WAKEUP)
			pr_info("wakeup wake lock(%s): %s\n",
				ns->tag, lock->name);
		wait_for_wakeup = 0;
		lock->stat.wakeup_count++;
	}
	if ((lock->flags & WAKE_LOCK_AUTO_EXPIRE) &&
	    (long)(lock->expires - jiffies) <= 0) {
		wake_unlock_stat_locked(lock, 0);
		lock->stat.last_time = ktime_get();
	}
#endif
	if (!(lock->flags & WAKE_LOCK_ACTIVE)) {
		lock->flags |= WAKE_LOCK_ACTIVE;
#ifdef CONFIG_WAKELOCK_STAT
		lock->stat.last_time = ktime_get();
#endif
	}

	list_del_init(&lock->link);

	/* get a namespace token for the lock */
	token = get_ns_token(lock, ns);
	if (token && !is_active_token(token)) {
		/*
		 * we're trying to lock in an inactive namespace:
		 * don't actually modify the lock's expiration time
		 */
		should_mod_lock = 0;
		/* increment the event num even though we don't mod the timer */
		current_event_num++;
	}

	if (has_timeout) {
		if (debug_mask & DEBUG_WAKE_LOCK)
			pr_info("wake_lock(%s): %s, type %d, "
				"timeout %ld.%03lu\n",
				ns->tag, lock->name, type, timeout / HZ,
				(timeout % HZ) * MSEC_PER_SEC / HZ);
		if (token) {
			token->timeout = timeout;
			token->flags |= WAKE_LOCK_AUTO_EXPIRE;
		}
		if (should_mod_lock) {
			lock->expires = jiffies + timeout;
			lock->flags |= WAKE_LOCK_AUTO_EXPIRE;
		}
		list_add_tail(&lock->link, &active_wake_locks[type]);
	} else {
		if (debug_mask & DEBUG_WAKE_LOCK)
			pr_info("wake_lock(%s): %s, type %d\n",
				ns->tag, lock->name, type);
		if (token)
			token->flags &= ~WAKE_LOCK_AUTO_EXPIRE;
		if (should_mod_lock) {
			lock->expires = LONG_MAX;
			lock->flags &= ~WAKE_LOCK_AUTO_EXPIRE;
		}
		list_add(&lock->link, &active_wake_locks[type]);
	}

	if (should_mod_lock)
		wake_lock_adjust_timer(lock, ns, timeout, has_timeout);

	spin_unlock_irqrestore(&list_lock, irqflags);
	if (debug_mask & DEBUG_WAKE_LOCK)
		pr_info("         (%s): %s LOCKED\n", ns->tag, lock->name);
}

void wake_lock(struct wake_lock *lock)
{
	wake_lock_internal(lock, current_dev_ns(), 0, 0);
}
EXPORT_SYMBOL(wake_lock);

void wake_lock_timeout(struct wake_lock *lock, long timeout)
{
	wake_lock_internal(lock, current_dev_ns(), timeout, 1);
}
EXPORT_SYMBOL(wake_lock_timeout);

/*
 * We can safely mark the wake lock inactive (unlocked) if:
 * 1. locked_by (token list) is empty - no other namespace has locked
 *     this lock, so its safe to mark inactive
 *
 * 2. we're in the init namespace (trust the kernel/drivers)
 *
 * 3. If the lock was taken in the init ns, and we're the active
 *    ns then let's go ahead and unlock (trust that locking was
 *    correct before virtualization)
 */
static inline int is_ok_to_unlock(struct wake_lock *lock,
				  struct dev_namespace *ns)
{
	struct wl_ns_token *t = NULL;

	/* no one else has a handle to this lock */
	if (list_empty(&lock->locked_by))
		return 1;

	/* we're the init ns */
	if (is_init_ns(ns))
		return 1;
	/*
	 * the last case is a bit trickier - we have to iterate over the
	 * locked_by list and ensure that the only other place this has been
	 * locked is the init ns, and that we're the active ns.
	 */
	if (!is_active_dev_ns(ns) || !list_is_singular(&lock->locked_by))
		return 0;

	t = list_first_entry(&lock->locked_by, struct wl_ns_token, link);
	if (is_init_ns(t->ns)) {
		pr_info("wake_lock(%s) locked by (KERNEL), unlocked by (%s)\n",
			 lock->name, ns->tag);
		return 1;
	}

	/* some other namespace has this lock: don't mark it inactive */
	return 0;
}

void wake_unlock(struct wake_lock *lock)
{
	int type;
	unsigned long irqflags;
	struct wl_ns_token *token = NULL;
	struct dev_namespace *ns = NULL;

	BUG_ON(!(lock->flags & WAKE_LOCK_INITIALIZED));

	ns = current_dev_ns();

	spin_lock_irqsave(&list_lock, irqflags);
	type = lock->flags & WAKE_LOCK_TYPE_MASK;

	(void)__wake_locked_in(lock, ns, &token);

	/* drop the namespace token associated with this wake lock */
	drop_ns_token(token);

	if (is_ok_to_unlock(lock, ns)) {
#ifdef CONFIG_WAKELOCK_STAT
		wake_unlock_stat_locked(lock, 0);
#endif
		if (debug_mask & DEBUG_WAKE_LOCK)
			pr_info("wake_unlock(%s): %s DEL\n",
				ns->tag, lock->name);
		lock->flags &= ~(WAKE_LOCK_ACTIVE | WAKE_LOCK_AUTO_EXPIRE);
		list_del(&lock->link);
		list_add(&lock->link, &inactive_locks);
	}

	/* adjust the timer */
	if (type == WAKE_LOCK_SUSPEND && is_active_token(token)) {
		long has_lock;
		struct nsproxy *nsp = NULL;

		/*
		 * when the init ns unlocks, adjust the timer based on the
		 * currently active namespace
		 */
		if (is_init_ns(ns))
			ns = active_dev_ns;
		nsp = dev_ns_nsproxy(ns);
		has_lock = has_wake_lock_locked_in(type, ns);

		if (has_lock > 0) {
			if (debug_mask & DEBUG_EXPIRE)
				pr_info("wake_unlock(%s): %s, "
					"start expire timer, %ld\n",
					ns->tag, lock->name, has_lock);
			mod_timer(&expire_timer, jiffies + has_lock);
			/*
			 * pass the nsproxy of the process
			 * modifying the timer
			 */
			expire_timer.data = (unsigned long)nsp;
		} else {
			if (del_timer(&expire_timer))
				if (debug_mask & DEBUG_EXPIRE)
					pr_info("wake_unlock(%s): %s, "
						"stop expire timer\n",
						ns->tag, lock->name);
			if (has_lock == 0) {
				if (debug_mask & DEBUG_EXPIRE)
					pr_info("wakelock: unlock(%s): "
						"has no active locks, queuing"
						" suspend work\n", ns->tag);
				queue_work_in(nsp, suspend_work_queue,
					      &suspend_work);
			}
		}
		if (lock == &main_wake_lock) {
			if (debug_mask & DEBUG_SUSPEND)
				print_active_locks(WAKE_LOCK_SUSPEND);
#ifdef CONFIG_WAKELOCK_STAT
			update_sleep_wait_stats_locked(0);
#endif
		}
	}
	spin_unlock_irqrestore(&list_lock, irqflags);
}
EXPORT_SYMBOL(wake_unlock);

int wake_lock_active(struct wake_lock *lock)
{
	return !!wake_locked_in(lock, current_dev_ns());
}
EXPORT_SYMBOL(wake_lock_active);

static inline void wake_lock_adjust_timer(struct wake_lock *lock,
					  struct dev_namespace *ns,
					  long timeout,
					  int has_timeout)
{
	int type = lock->flags & WAKE_LOCK_TYPE_MASK;
	if (type == WAKE_LOCK_SUSPEND) {
		long expire_in = 0;
		current_event_num++;
#ifdef CONFIG_WAKELOCK_STAT
		if (lock == &main_wake_lock)
			update_sleep_wait_stats_locked(1);
		else if (!__wake_locked_in(&main_wake_lock, ns, NULL))
			update_sleep_wait_stats_locked(0);
#endif
		if (has_timeout)
			expire_in = has_wake_lock_locked_in(type, ns);
		else
			expire_in = -1;
		if (expire_in > 0) {
			if (debug_mask & DEBUG_EXPIRE)
				pr_info("wake_lock: %s, start expire timer, "
					"%ld\n", lock->name, expire_in);
			/* pass the namespace which called the timer mod */
			expire_timer.data = (unsigned long)
				dev_ns_nsproxy(ns);
			mod_timer(&expire_timer, jiffies + expire_in);
		} else {
			if (del_timer(&expire_timer))
				if (debug_mask & DEBUG_EXPIRE)
					pr_info("wake_lock(%s): %s, "
						"stop expire timer\n", ns->tag,
						lock->name);
			if (expire_in == 0) {
				struct nsproxy *nsp = dev_ns_nsproxy(ns);
				pr_info("wake_lock(%s): %s, "
					"queuing suspend work",
					ns->tag, lock->name);
				queue_work_in(nsp, suspend_work_queue,
					      &suspend_work);
			}
		}
	}
}

static int wakelock_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, wakelock_stats_show, NULL);
}

static const struct file_operations wakelock_stats_fops = {
	.owner = THIS_MODULE,
	.open = wakelock_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init wakelocks_init(void)
{
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(active_wake_locks); i++)
		INIT_LIST_HEAD(&active_wake_locks[i]);

#ifdef CONFIG_WAKELOCK_STAT
	wake_lock_init(&deleted_wake_locks, WAKE_LOCK_SUSPEND,
			"deleted_wake_locks");
#endif
	wake_lock_init(&main_wake_lock, WAKE_LOCK_SUSPEND, "main");
	wake_lock(&main_wake_lock);
	wake_lock_init(&unknown_wakeup, WAKE_LOCK_SUSPEND, "unknown_wakeups");
	wake_lock_init(&suspend_backoff_lock, WAKE_LOCK_SUSPEND,
		       "suspend_backoff");

	ret = platform_device_register(&power_device);
	if (ret) {
		pr_err("wakelocks_init: platform_device_register failed\n");
		goto err_platform_device_register;
	}
	ret = platform_driver_register(&power_driver);
	if (ret) {
		pr_err("wakelocks_init: platform_driver_register failed\n");
		goto err_platform_driver_register;
	}

	INIT_COMPLETION(suspend_sys_sync_comp);
	suspend_sys_sync_work_queue =
		create_singlethread_workqueue("suspend_sys_sync");
	if (suspend_sys_sync_work_queue == NULL) {
		ret = -ENOMEM;
		goto err_suspend_sys_sync_work_queue;
	}

	suspend_work_queue = create_singlethread_workqueue("suspend");
	if (suspend_work_queue == NULL) {
		ret = -ENOMEM;
		goto err_suspend_work_queue;
	}

#ifdef CONFIG_DEV_NS
	pr_info("wakelocks_init: registering for all namespace events\n");
	dev_ns_register_notify(NULL, &wake_lock_ns_switch_notifier);
#endif
#ifdef CONFIG_WAKELOCK_STAT
	proc_create("wakelocks", S_IRUGO, NULL, &wakelock_stats_fops);
#endif

	return 0;

err_suspend_sys_sync_work_queue:
err_suspend_work_queue:
	platform_driver_unregister(&power_driver);
err_platform_driver_register:
	platform_device_unregister(&power_device);
err_platform_device_register:
	wake_lock_destroy(&suspend_backoff_lock);
	wake_lock_destroy(&unknown_wakeup);
	wake_lock_destroy(&main_wake_lock);
#ifdef CONFIG_WAKELOCK_STAT
	wake_lock_destroy(&deleted_wake_locks);
#endif

	debug_mask = DEBUG_EXIT_SUSPEND | DEBUG_WAKEUP |
		     DEBUG_SUSPEND | DEBUG_EXPIRE;
	return ret;
}

static void  __exit wakelocks_exit(void)
{
#ifdef CONFIG_WAKELOCK_STAT
	remove_proc_entry("wakelocks", NULL);
#endif
#ifdef CONFIG_DEV_NS
	pr_info("wakelocks_exit: de-registering for namespace events\n");
	dev_ns_unregister_notify(NULL, &wake_lock_ns_switch_notifier);
#endif
	destroy_workqueue(suspend_work_queue);
	destroy_workqueue(suspend_sys_sync_work_queue);
	platform_driver_unregister(&power_driver);
	platform_device_unregister(&power_device);
	wake_lock_destroy(&suspend_backoff_lock);
	wake_lock_destroy(&unknown_wakeup);
	wake_lock_destroy(&main_wake_lock);
#ifdef CONFIG_WAKELOCK_STAT
	wake_lock_destroy(&deleted_wake_locks);
#endif
}

core_initcall(wakelocks_init);
module_exit(wakelocks_exit);

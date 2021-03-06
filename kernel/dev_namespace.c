/*
 * kernel/dev_namespace.c
 *
 * Copyright (c) 2010-2011 Columbia University
 * Authors:
 *    Christoffer Dall <cdall@cs.columbia.edu>
 *    Jeremy C. Andrus <jeremya@cs.columbia.edu>
 *
 * Copyright (c) 2011-2013 Cellrox Ltd. Certain portions are copyrighted by
 * Columbia University. This program is free software licensed under the GNU
 * General Public License Version 2 (GPL 2). You can distribute it and/or
 * modify it under the terms of the GPL 2.
 *
 *
 * Device namespaces:
 *
 * The idea with a device namespace comes from the Android-Cells project where
 * namespaces are utilized to create a container-like environment on Linux, only
 * where there's a notion of an 'active' namespace and all other namespaces are
 * inactive. In such a case only processes residing within the active device
 * namespace should communicate with actual devices, where processes inside
 * inactive containers should be able to communicate gracefully with the device
 * driver, but not the device.
 *
 * The device namespace allows a device driver to register itself and pass a
 * pointer to its device specific namespace structure and register notifiers
 * which are called when the active namepace becomes inactive and when an
 * inactive namespace becomes active.
 *
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 * The full GPL 2 License is included in this distribution in the file called
 * COPYING
 *
 * Cellrox can be contacted at oss@cellrox.com
 */

#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/pid_namespace.h>
#include <linux/dev_namespace.h>
#include <linux/wakelock.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>


/* protects active namespace and switches */
static DECLARE_RWSEM(global_dev_ns_lock);

static void dev_ns_lock(struct dev_namespace *dev_ns)
{
	mutex_lock(&dev_ns->mutex);
}

static void dev_ns_unlock(struct dev_namespace *dev_ns)
{
	mutex_unlock(&dev_ns->mutex);
}

static struct dev_namespace *create_dev_ns(struct task_struct *task,
					   struct pid_namespace *new_pidns)
{
	struct dev_namespace *dev_ns;

	static int s_ndev;

	dev_ns = kzalloc(sizeof(struct dev_namespace), GFP_KERNEL);
	if (!dev_ns)
		return ERR_PTR(-ENOMEM);

	atomic_set(&dev_ns->count, 1);
	BLOCKING_INIT_NOTIFIER_HEAD(&dev_ns->notifiers);
	mutex_init(&dev_ns->mutex);
	/* all new namespaces get a default tag */
	snprintf(dev_ns->tag, DEV_NS_TAG_LEN, "dev_ns.%d", ++s_ndev);
	dev_ns->tag[DEV_NS_TAG_LEN-1] = '\0';

	dev_ns->pid_ns = get_pid_ns(new_pidns);

	return dev_ns;
}

struct dev_namespace *copy_dev_ns(unsigned long flags,
				  struct task_struct *task,
				  struct pid_namespace *new_pidns)
{
	struct dev_namespace *dev_ns = task->nsproxy->dev_ns;

	/*
	 * Couple device namespace semantics with pid-namespace.
	 * It's convenient, and we ran out of clone flags anyway.
	 */
	if (!(flags & CLONE_NEWPID))
		return get_dev_ns(dev_ns);
	else
		return create_dev_ns(task, new_pidns);
}

void __put_dev_ns(struct dev_namespace *dev_ns)
{
	int n;

	if (!dev_ns || dev_ns == &init_dev_ns)
		return;

	for (n = 0; n < DEV_NS_DESC_MAX; n++) {
		if (dev_ns->info[n])
			put_dev_ns_info(n, dev_ns->info[n], 0);
	}

	put_pid_ns(dev_ns->pid_ns);
	kfree(dev_ns);
}

struct dev_namespace *get_dev_ns_by_task(struct task_struct *task)
{
	struct dev_namespace *dev_ns = NULL;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = task_nsproxy(task);
	if (nsproxy)
		dev_ns = get_dev_ns(nsproxy->dev_ns);
	rcu_read_unlock();

	return dev_ns;
}

struct dev_namespace *get_dev_ns_by_vpid(pid_t vpid)
{
	struct dev_namespace *dev_ns = NULL;
	struct task_struct *task;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	task = find_task_by_pid_ns(vpid, &init_pid_ns);
	if (task) {
		nsproxy = task_nsproxy(task);
		if (nsproxy)
			dev_ns = get_dev_ns(nsproxy->dev_ns);
	}
	rcu_read_unlock();

	return dev_ns;
}

/**
 * notifications: activate/deactive device namespace
 */
static BLOCKING_NOTIFIER_HEAD(dev_ns_notifiers);
void dev_ns_register_notify(struct dev_namespace *dev_ns,
			    struct notifier_block *nb)
{
	if (dev_ns != NULL)
		blocking_notifier_chain_register(&dev_ns->notifiers, nb);
	else
		blocking_notifier_chain_register(&dev_ns_notifiers, nb);
}

void dev_ns_unregister_notify(struct dev_namespace *dev_ns,
			      struct notifier_block *nb)
{
	if (dev_ns != NULL)
		blocking_notifier_chain_unregister(&dev_ns->notifiers, nb);
	else
		blocking_notifier_chain_unregister(&dev_ns_notifiers, nb);
}

/*
 * Helpers for per-driver logic of device-namepace
 *
 * Drivers should embed 'struct dev_ns_info' in driver-specific,
 * per-device-namespace data, e.g.:
 *
 *   struct xxxx_namespace {
 *     ... (data specific to xxxx)
 *     struct dev_ns_info devns_info;
 *   };
 *
 * Drivers should register a 'struct dev_ns_ops' with ->create()
 * and ->release() methods, and keep an identifier (dev_ns_xxx_id),
 * for use by device namespace generic code
 *
 * Drivers can iterate over per-driver data in all namespaces:
 *   void loop_dev_ns_info(int dev_ns_id, void *ptr,
 *              void (*func)(struct dev_ns_info *dev_ns_info, void *ptr))
 *
 * See include/linux/dev_namespace.h for helper macros to hide these details.
 */

struct dev_ns_desc {
	char *name;
	struct dev_ns_ops *ops;
	struct mutex mutex;
	struct list_head head;
};

static struct dev_ns_desc dev_ns_desc[DEV_NS_DESC_MAX];
static DEFINE_SPINLOCK(dev_ns_desc_lock);

int register_dev_ns_ops(char *name, struct dev_ns_ops *ops)
{
	struct dev_ns_desc *desc;
	int n, ret = -ENOMEM;

	if (!name)
		return -EINVAL;

	spin_lock(&dev_ns_desc_lock);
	for (n = 0; n < DEV_NS_DESC_MAX; n++) {
		desc = &dev_ns_desc[n];
		if (!desc->name && ret < 0)
			ret = n;
		else if (desc->name && !strcmp(desc->name, name)) {
			ret = -EBUSY;
			break;
		}
	}
	if (ret >= 0) {
		pr_info("dev_ns: register info %s\n", name);
		desc = &dev_ns_desc[ret];
		desc->name = name;
		desc->ops = ops;
		INIT_LIST_HEAD(&desc->head);
		mutex_init(&desc->mutex);
	}
	spin_unlock(&dev_ns_desc_lock);

	return ret;
}

void unregister_dev_ns_ops(int dev_ns_id)
{
	struct dev_ns_desc *desc = &dev_ns_desc[dev_ns_id];

	spin_lock(&dev_ns_desc_lock);
	pr_info("dev_ns: unregister desc %s\n", desc->name);
	memset(&dev_ns_desc[dev_ns_id], 0, sizeof(*desc));
	spin_unlock(&dev_ns_desc_lock);
}

/* this function is called with dev_ns_lock(dev_ns) held */
static struct dev_ns_info *new_dev_ns_info(int dev_ns_id,
					   struct dev_namespace *dev_ns)
{
	struct dev_ns_desc *desc = &dev_ns_desc[dev_ns_id];
	struct dev_ns_info *dev_ns_info;

	pr_debug("dev_ns: [0x%p] new info %s\n", dev_ns, desc->name);

	dev_ns_info = desc->ops->create(dev_ns);
	if (IS_ERR_OR_NULL(dev_ns_info))
		return NULL;

	pr_debug("dev_ns: [0x%p] got info 0x%p\n", dev_ns, dev_ns_info);

	dev_ns->info[dev_ns_id] = dev_ns_info;
	/* take a reference for our dev_ns_info array */
	atomic_set(&dev_ns_info->count, 1);
	/*
	 * don't take a reference here: we're contained by the dev_namespace
	 * structure, and an extra reference to that structure would create a
	 * circular dependecy resulting in memory that can never be free'd.
	 */
	dev_ns_info->dev_ns = dev_ns;

	mutex_lock(&desc->mutex);
	list_add(&dev_ns_info->list, &desc->head);
	mutex_unlock(&desc->mutex);

	return dev_ns_info;
}

/* this function is called with dev_ns_lock(dev_ns) held */
static void del_dev_ns_info(int dev_ns_id, struct dev_ns_info *dev_ns_info)
{
	struct dev_ns_desc *desc = &dev_ns_desc[dev_ns_id];
	struct dev_namespace *dev_ns = dev_ns_info->dev_ns;

	pr_debug("dev_ns: [0x%p] destory info 0x%p\n", dev_ns, dev_ns_info);

	dev_ns->info[dev_ns_id] = NULL;
	mutex_lock(&desc->mutex);
	list_del(&dev_ns_info->list);
	mutex_unlock(&desc->mutex);

	dev_ns_desc[dev_ns_id].ops->release(dev_ns_info);
}

/*
 * get_dev_ns_info() is intended for internal use only. It is exported only
 * to enable the helper macros in dev_namepsace.h to work properly.
 *
 * @create tells whether to create a new instance if none is found already,
 * or just return NULL.
 *
 * @lock tells whether the @dev_ns should be locked against concurrent
 * changes, or the caller is the one responsible (in which case there is
 * not even a need for an extra refefence count).
 */
struct dev_ns_info *get_dev_ns_info(int dev_ns_id,
				    struct dev_namespace *dev_ns,
				    bool lock, bool create)
{
	struct dev_ns_info *dev_ns_info;

	if (lock) {
		down_read(&global_dev_ns_lock);
		dev_ns_lock(dev_ns);
	}

	dev_ns_info = dev_ns->info[dev_ns_id];

	if (!dev_ns_info && create)
		dev_ns_info = new_dev_ns_info(dev_ns_id, dev_ns);

	if (dev_ns_info) {
		pr_debug("dev_ns: [0x%p] get info 0x%p count %d+\n", dev_ns,
			 dev_ns_info, atomic_read(&dev_ns_info->count));
	}

	if (dev_ns_info && lock)
		atomic_inc(&dev_ns_info->count);

	if (lock) {
		dev_ns_unlock(dev_ns);
		up_read(&global_dev_ns_lock);
	}

	return dev_ns_info;
}

struct dev_ns_info *get_dev_ns_info_task(int dev_ns_id, struct task_struct *tsk)
{
	struct dev_ns_info *dev_ns_info = NULL;
	struct dev_namespace *dev_ns;

	dev_ns = get_dev_ns_by_task(tsk);
	if (dev_ns) {
		dev_ns_info = get_dev_ns_info(dev_ns_id, dev_ns, 1, 1);
		put_dev_ns(dev_ns);
	}

	return dev_ns_info;
}

void put_dev_ns_info(int dev_ns_id, struct dev_ns_info *dev_ns_info, int lock)
{
	struct dev_namespace *dev_ns = dev_ns_info->dev_ns;

	if (lock) {
		down_read(&global_dev_ns_lock);
		dev_ns_lock(dev_ns);
	}

	pr_debug("dev_ns: [0x%p] put info 0x%p count %d-\n", dev_ns,
		 dev_ns_info, atomic_read(&dev_ns_info->count));
	if (atomic_dec_and_test(&dev_ns_info->count))
		del_dev_ns_info(dev_ns_id, dev_ns_info);

	if (lock) {
		dev_ns_unlock(dev_ns);
		up_read(&global_dev_ns_lock);
	}
}

/*
 * @dev_ns_id: id of device namespace subsystem
 * @ptr: data pointer to be passed to callback
 * @func: callback for each device namespace (atomic, must not sleep)
 */
void loop_dev_ns_info(int dev_ns_id, void *ptr,
		      void (*func)(struct dev_ns_info *dev_ns_info, void *ptr))
{
	struct dev_ns_desc *desc = &dev_ns_desc[dev_ns_id];
	struct dev_ns_info *dev_ns_info;

	mutex_lock(&desc->mutex);
	list_for_each_entry(dev_ns_info, &desc->head, list) {
		pr_debug("dev_ns: loop info 0x%p (dev_ns 0x%p) of %s\n",
			 dev_ns_info, dev_ns_info->dev_ns, desc->name);
		(*func)(dev_ns_info, ptr);
	}
	mutex_unlock(&desc->mutex);
}

/**
 * Set the active device namespace (will call registered notifiers to
 * allow device drivers to make device specific context store/restore)
 *
 * @dev_ns: The new active device namespace
 */
void set_active_dev_ns(struct dev_namespace *next_ns)
{
	struct dev_namespace *prev_ns;

	BUG_ON(next_ns == NULL);

	down_write(&global_dev_ns_lock);

	if (next_ns == active_dev_ns)
		goto done;

	pr_info("dev_ns: activate 0x%p\n", next_ns);

	prev_ns = active_dev_ns;

	/*
	 * deactivate previous dev_ns:
	 * - set active-state of previous dev_ns to false
	 * - call previous dev_ns's notifiers with deactivate event
	 * - call global notifiers with deactivate event
	 */

	dev_ns_lock(prev_ns);

	prev_ns->active = false;
	prev_ns->timestamp = jiffies;

	(void) blocking_notifier_call_chain(&prev_ns->notifiers,
					    DEV_NS_EVENT_DEACTIVATE, prev_ns);
	(void) blocking_notifier_call_chain(&dev_ns_notifiers,
					    DEV_NS_EVENT_DEACTIVATE, prev_ns);

	dev_ns_unlock(prev_ns);

	/*
	 * activate next dev_ns:
	 * - set active-state of next dev_ns to true
	 * - call next dev_ns's notifiers with activate event
	 * - call global notifiers with activate event
	 */

	dev_ns_lock(next_ns);

	next_ns->active = true;
	next_ns->timestamp = jiffies;

	/* make the switch */
	active_dev_ns = next_ns;

	(void) blocking_notifier_call_chain(&next_ns->notifiers,
					    DEV_NS_EVENT_ACTIVATE, next_ns);
	(void) blocking_notifier_call_chain(&dev_ns_notifiers,
					    DEV_NS_EVENT_ACTIVATE, next_ns);

	dev_ns_unlock(next_ns);

	get_dev_ns(next_ns);
	put_dev_ns(prev_ns);

	pr_info("dev_ns: activate 0x%p done\n", next_ns);
 done:
	up_write(&global_dev_ns_lock);
}

void get_dev_ns_tag(char *to, struct dev_namespace *dev_ns)
{
	/* buf must be at least sizeof(dev_ns->tag) in size */
	to[DEV_NS_TAG_LEN] = '\0';
	strncpy(to, dev_ns->tag, DEV_NS_TAG_LEN);
}

void set_dev_ns_tag(struct dev_namespace *dev_ns, char *from)
{
	dev_ns_lock(dev_ns);
	strncpy(dev_ns->tag, from, DEV_NS_TAG_LEN);
	dev_ns_unlock(dev_ns);
}


/**
 * Setup for /proc/dev_ns
 */

static struct proc_dir_entry *proc_dev_ns_dir;

struct proc_dir_entry *
create_dev_ns_proc(const char *name, const struct file_operations *fops)
{
	struct proc_dir_entry *entry;
	entry = proc_create(name, 0, proc_dev_ns_dir, fops);
	return entry;
}

static int proc_active_ns_show(struct seq_file *seq, void *offset)
{
	down_read(&global_dev_ns_lock);
	seq_printf(seq, "%d\n", dev_ns_init_pid(active_dev_ns));
	up_read(&global_dev_ns_lock);
	return 0;
}

static int proc_ns_tag_show(struct seq_file *seq, void *offset)
{
	down_read(&global_dev_ns_lock);
	seq_printf(seq, "active: %d timestamp: %ld tag: %s\n",
		   dev_ns_init_pid(active_dev_ns),
		   active_dev_ns->timestamp,
		   active_dev_ns->tag);
	up_read(&global_dev_ns_lock);
	return 0;
}

static bool dev_ns_proc_permission(void)
{
	return current_dev_ns() == &init_dev_ns;
}

static int proc_active_ns_open(struct inode *inode, struct file *file)
{
	if (!dev_ns_proc_permission())
		return -EPERM;
	return single_open(file, proc_active_ns_show, PDE(inode)->data);
}

static int proc_ns_tag_open(struct inode *inode, struct file *file)
{
	if (!dev_ns_proc_permission())
		return -EPERM;
	return single_open(file, proc_ns_tag_show, PDE(inode)->data);
}

static ssize_t dev_ns_proc_write(struct file *file,
				 const char __user *buffer,
				 size_t count, loff_t *ppos, int setactive)
{
	struct dev_namespace *dev_ns;
	char strbuf[16]; /* 10 chars for 32-bit pid + ':' + 4 chars for tag */
	char *pid_str, *tag_str;
	pid_t new_pid = 0;

	/* only init ns may change active ns */
	if (!dev_ns_proc_permission())
		return -EPERM;

	if (count >= sizeof(strbuf) || count == 0)
		return -EFAULT;

	if (copy_from_user(strbuf, buffer, count))
		return -EFAULT;

	strbuf[count] = '\0';
	pid_str = strim(strbuf);
	tag_str = strchr(pid_str, ':');
	if (tag_str)
		*(tag_str++) = '\0';

	if (kstrtoint(pid_str, 10, &new_pid) || !new_pid) {
		pr_warning("dev_ns: bad PID format '%s'\n", pid_str);
		return -EINVAL;
	}

	dev_ns = get_dev_ns_by_vpid(new_pid);
	if (!dev_ns) {
		pr_warning("dev_ns: non-existing PID %d\n", new_pid);
		return -EINVAL;
	}

	if (setactive) {
		set_active_dev_ns(dev_ns);
	} else if (tag_str) {
		/* set dev_ns tag if format was <pid>:<tag> */
		/* (safe: last byte of tag always remains NULL) */
		set_dev_ns_tag(dev_ns, tag_str);
	} else {
		pr_warning("dev_ns: bad PID:tag format '%s'\n", pid_str);
		count = -EINVAL;
	}

	put_dev_ns(dev_ns);
	return count;
}

static ssize_t proc_active_ns_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *ppos)
{
	return dev_ns_proc_write(file, buffer, count, ppos, 1);
}

static ssize_t proc_ns_tag_write(struct file *file,
				 const char __user *buffer,
				 size_t count, loff_t *ppos)
{
	return dev_ns_proc_write(file, buffer, count, ppos, 0);
}

static const struct file_operations active_ns_fileops = {
	.owner = THIS_MODULE,
	.open = proc_active_ns_open,
	.read = seq_read,
	.write = proc_active_ns_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations ns_tag_fileops = {
	.owner = THIS_MODULE,
	.open = proc_ns_tag_open,
	.read = seq_read,
	.write = proc_ns_tag_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static __init int dev_namespace_init(void)
{
	struct proc_dir_entry *entry;

	proc_dev_ns_dir = proc_mkdir("dev_ns", NULL);
	if (!proc_dev_ns_dir)
		return -ENOMEM;

	entry = proc_create("active_ns_pid", 0644, proc_dev_ns_dir,
			    &active_ns_fileops);
	if (!entry)
		goto out_fail_active_ns;

	entry = proc_create("ns_tag", 0644, proc_dev_ns_dir,
			    &ns_tag_fileops);
	if (!entry)
		goto out_fail_ns_tag;

	return 0;

out_fail_ns_tag:
	remove_proc_entry("active_ns_pid", proc_dev_ns_dir);
out_fail_active_ns:
	remove_proc_entry("dev_ns", NULL);
	return -ENOMEM;
}

device_initcall(dev_namespace_init);

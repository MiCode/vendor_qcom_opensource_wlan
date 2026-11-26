// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012,2014-2017,2019-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/jiffies.h>
#include "cnss_common.h"
#ifdef CONFIG_CNSS_OUT_OF_TREE
#include "cnss_prealloc.h"
#else
#include <net/cnss_prealloc.h>
#endif

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CNSS prealloc driver");

static bool cnss_prealloc_sysfs_stats;

#ifdef CONFIG_CNSS2_DEBUG
#define CNSS_ASSERT(_condition) do {					\
		if (!(_condition)) {					\
			pr_err("ASSERT at line %d\n",			\
			       __LINE__);				\
			BUG();						\
		}							\
	} while (0)
#else
#define CNSS_ASSERT(_condition) do {					\
		if (!(_condition)) {					\
			pr_err("ASSERT at line %d\n",			\
			       __LINE__);				\
			WARN_ON(1);					\
		}							\
	} while (0)
#endif


/* cnss preallocation scheme is a memory pool that always tries to keep a
 * list of free memory for use in emergencies. It is implemented on kernel
 * features: memorypool and kmem cache.
 */

#define CNSS_STACK_TRACE_DEPTH 16
#define CNSS_SYMBOL_NAME_LEN KSYM_SYMBOL_LEN

struct cnss_stack_entry {
	char symbol[CNSS_SYMBOL_NAME_LEN];
	unsigned long offset;
	unsigned long size;
};

struct cnss_alloc_info {
	void *ptr;
	struct cnss_stack_entry stack_entries[CNSS_STACK_TRACE_DEPTH];
	unsigned int nr_entries;
	unsigned long timestamp;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	size_t requested_size;
};

/*
 * Structure to hold statistics for each memory pool.
 */
struct cnss_pool_stats {
	size_t alloc_count;
	size_t free_count;
	size_t current_bytes_allocated;
	size_t peak_bytes_allocated;
	size_t larger_pool_alloc_count;
	size_t wasted_bytes_larger_pool; /* Accumulated wasted bytes */
};

struct cnss_pool {
	size_t size;
	int min;
	const char name[50];
	mempool_t *mp;
	struct kmem_cache *cache;
	void **pool_ptrs;
	/* Keep it always zero if stack trace feature not enabled */
	struct cnss_alloc_info *alloc_info;
	int table_capacity;
	struct cnss_pool_stats stats;
	struct kobject kobj;
};

/**
 * Memory pool
 * -----------
 *
 * How to update this table:
 *
 *  1. Add a new row with following elements
 *      size  : Size of one allocation unit in bytes.
 *      min   : Minimum units to be reserved. Used only if a regular
 *              allocation fails.
 *      name  : Name of the cache/pool. Will be displayed in /proc/slabinfo
 *              if not merged with another pool.
 *      mp    : A pointer to memory pool. Updated during init.
 *      cache : A pointer to cache. Updated during init.
 *      pool_ptrs: A table to keep track of memory allocated from the pool.
 *      table_capacity: Total capacity of the tracker table for the pool.
 * 2. Always keep the table in increasing order
 * 3. Please keep the reserve pool as minimum as possible as it's always
 *    preallocated.
 * 4. Always profile with different use cases after updating this table.
 * 5. A dynamic view of this pool can be viewed at /proc/slabinfo.
 * 6. Each pool has a sys node at /sys/kernel/slab/<name>
 *
 */

/* size, min pool reserve, name, memorypool handler, cache handler*/
static struct cnss_pool cnss_pools_default[] = {
	{16 * 1024, 16, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 22, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 38, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 16, "cnss-pool-128k", NULL, NULL, NULL},
	{256 * 1024, 4, "cnss-pool-256k", NULL, NULL, NULL},
};

static struct cnss_pool cnss_pools_adrastea[] = {
	{16 * 1024, 8, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 8, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 3, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 0, "cnss-pool-128k", NULL, NULL, NULL},
};

static struct cnss_pool cnss_pools_wcn6750[] = {
	{16 * 1024, 8, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 11, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 15, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 4, "cnss-pool-128k", NULL, NULL, NULL},
};

static struct cnss_pool cnss_pools_wcn7750[] = {
	{16 * 1024, 16, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 22, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 38, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 10, "cnss-pool-128k", NULL, NULL, NULL},
	{256 * 1024, 2, "cnss-pool-256k", NULL, NULL, NULL},
};

#ifdef CONFIG_CNSS2_DEBUG
static struct cnss_pool cnss_pools_wcn6450[] = {
	{16 * 1024, 24, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 14, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 36, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 10, "cnss-pool-128k", NULL, NULL, NULL},
};

static struct cnss_pool cnss_pools_fig[] = {
	{16 * 1024, 80, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 62, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 44, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 14, "cnss-pool-128k", NULL, NULL, NULL},
	{256 * 1024, 4, "cnss-pool-256k", NULL, NULL, NULL},
};
#else

static struct cnss_pool cnss_pools_wcn6450[] = {
	{16 * 1024, 14, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 10, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 8, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 5, "cnss-pool-128k", NULL, NULL, NULL},
};

static struct cnss_pool cnss_pools_fig[] = {
	{16 * 1024, 68, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 62, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 10, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 9, "cnss-pool-128k", NULL, NULL, NULL},
	{256 * 1024, 1, "cnss-pool-256k", NULL, NULL, NULL},
};
#endif

struct cnss_pool *cnss_pools;
unsigned int cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_default);
spinlock_t pool_table_lock;
bool mempool_initialization_done;
bool cnss_force_prealloc_pool;

/* Kobject for the cnss_prealloc module sysfs entry */
static struct kobject *cnss_prealloc_kobj;

static ssize_t enable_stats_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", cnss_prealloc_sysfs_stats);
}

static ssize_t enable_stats_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	bool val;
	int ret;

	if (mempool_initialization_done) {
		pr_err("cnss_prealloc: Cannot change stats enablement after pool init\n");
		return -EPERM;
	}

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (cnss_prealloc_sysfs_stats && !val) {
		pr_err("cnss_prealloc: Cannot disable stats once enabled\n");
		return -EPERM;
	}

	cnss_prealloc_sysfs_stats = val;
	return count;
}

static struct kobj_attribute enable_stats_attribute = __ATTR_RW(enable_stats);

/* Sysfs attribute show functions */
#define DEFINE_POOL_ATTR_RO(_name) \
static ssize_t _name##_show(struct kobject *kobj, struct kobj_attribute *attr, \
			 char *buf) \
{ \
	struct cnss_pool *pool = container_of(kobj, struct cnss_pool, kobj); \
	return sysfs_emit(buf, "%zu\n", pool->stats._name); \
} \
static struct kobj_attribute _name##_attribute = __ATTR_RO(_name);

DEFINE_POOL_ATTR_RO(alloc_count);
DEFINE_POOL_ATTR_RO(free_count);
DEFINE_POOL_ATTR_RO(current_bytes_allocated);
DEFINE_POOL_ATTR_RO(peak_bytes_allocated);
DEFINE_POOL_ATTR_RO(larger_pool_alloc_count);
DEFINE_POOL_ATTR_RO(wasted_bytes_larger_pool);

static struct attribute *cnss_pool_attrs[] = {
	&alloc_count_attribute.attr,
	&free_count_attribute.attr,
	&current_bytes_allocated_attribute.attr,
	&peak_bytes_allocated_attribute.attr,
	&larger_pool_alloc_count_attribute.attr,
	&wasted_bytes_larger_pool_attribute.attr,
	NULL,
};

static struct attribute_group cnss_pool_attr_group = {
	.attrs = cnss_pool_attrs,
};

static ssize_t active_allocations_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct cnss_pool *pool = container_of(kobj, struct cnss_pool, kobj);
	ssize_t count = 0;
	unsigned long irq_flags;
	int i, len;
	struct cnss_alloc_info *alloc_info;
	int remaining = PAGE_SIZE;

	spin_lock_irqsave(&pool_table_lock, irq_flags);

	len = scnprintf(buf + count, remaining,
			"Active Allocations for %s (size %zu, capacity %d):\n",
			pool->name, pool->size, pool->table_capacity);
	count += len;
	remaining -= len;

	len = scnprintf(buf + count, remaining,
			"--------------------------------------------------\n");
	count += len;
	remaining -= len;

	alloc_info = pool->alloc_info;
	if (alloc_info) {
		for (i = 0; i < pool->table_capacity; i++) {
			if (remaining <= 0)
				break;

			if (pool->pool_ptrs[i] && alloc_info[i].ptr == pool->pool_ptrs[i]) {
				const char *caller1 = alloc_info[i].nr_entries > 2 ?
						     alloc_info[i].stack_entries[2].symbol : "unknown";
				const char *caller2 = alloc_info[i].nr_entries > 3 ?
						     alloc_info[i].stack_entries[3].symbol : "unknown";

				len = scnprintf(buf + count, remaining,
						"  Addr: %pK, Req: %zu, Actual: %zu, Caller: %s, %s, Time: %lu, PID: %d, Comm: %s\n",
						alloc_info[i].ptr,
						alloc_info[i].requested_size,
						pool->size,
						caller1,
						caller2,
						alloc_info[i].timestamp,
						alloc_info[i].pid,
						alloc_info[i].comm);
				count += len;
				remaining -= len;
			}
		}
	} else {
		if (remaining > 0) {
			len = scnprintf(buf + count, remaining,
					"Stack tracking disabled or not initialized.\n");
			count += len;
			remaining -= len;
		}
	}

	spin_unlock_irqrestore(&pool_table_lock, irq_flags);
	return count;
}

static struct kobj_attribute active_allocations_attribute =
	__ATTR(active_allocations, 0444, active_allocations_show, NULL);

static struct attribute *cnss_pool_debug_attrs[] = {
	&active_allocations_attribute.attr,
	NULL,
};

static struct attribute_group cnss_pool_debug_attr_group = {
	.attrs = cnss_pool_debug_attrs,
};

static void cnss_pool_kobj_release(struct kobject *kobj)
{
	struct cnss_pool *pool = container_of(kobj, struct cnss_pool, kobj);
	pr_debug("cnss_prealloc: kobject %s released\n", pool->name);
}

static struct kobj_type cnss_pool_kobj_type = {
	.release = cnss_pool_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
};

static int cnss_prealloc_sysfs_init(void)
{
	int ret;

	cnss_prealloc_kobj = kobject_create_and_add("cnss_prealloc", kernel_kobj);
	if (!cnss_prealloc_kobj) {
		pr_err("cnss_prealloc: failed to create cnss_prealloc kobject\n");
		return -ENOMEM;
	}

	ret = sysfs_create_file(cnss_prealloc_kobj, &enable_stats_attribute.attr);
	if (ret) {
		pr_err("cnss_prealloc: failed to create enable_stats file\n");
		kobject_put(cnss_prealloc_kobj);
		return ret;
	}

	return 0;
}

static void cnss_prealloc_sysfs_exit(void)
{
	if (cnss_prealloc_kobj) {
		sysfs_remove_file(cnss_prealloc_kobj, &enable_stats_attribute.attr);
		kobject_put(cnss_prealloc_kobj);
	}
}

static int cnss_pool_sysfs_init(struct cnss_pool *pool)
{
	int ret;

	if (!cnss_prealloc_kobj)
		return -ENODEV;

	memset(&pool->stats, 0, sizeof(struct cnss_pool_stats));

	ret = kobject_init_and_add(&pool->kobj, &cnss_pool_kobj_type,
				   cnss_prealloc_kobj, "%s", pool->name);
	if (ret) {
		pr_err("cnss_prealloc: failed to create kobject for %s\n",
		       pool->name);
		kobject_put(&pool->kobj);
		return ret;
	}

	ret = sysfs_create_group(&pool->kobj, &cnss_pool_attr_group);
	if (ret) {
		pr_err("cnss_prealloc: failed to create attribute group for %s\n",
		       pool->name);
		kobject_del(&pool->kobj);
		kobject_put(&pool->kobj);
		return ret;
	}

	ret = sysfs_create_group(&pool->kobj, &cnss_pool_debug_attr_group);
	if (ret) {
		pr_err("cnss_prealloc: failed to create debug attribute group for %s\n",
		       pool->name);
		sysfs_remove_group(&pool->kobj, &cnss_pool_attr_group);
		kobject_del(&pool->kobj);
		kobject_put(&pool->kobj);
		return ret;
	}

	return 0;
}

static void cnss_pool_sysfs_exit(struct cnss_pool *pool)
{
	if (!cnss_prealloc_kobj)
		return;

	pr_info("cnss_prealloc: Final stats for %s: alloc_count=%zu, free_count=%zu, current_bytes=%zu, peak_bytes=%zu, larger_pool_allocs=%zu, wasted_bytes=%zu\n",
		pool->name, pool->stats.alloc_count,
		pool->stats.free_count,
		pool->stats.current_bytes_allocated,
		pool->stats.peak_bytes_allocated,
		pool->stats.larger_pool_alloc_count,
		pool->stats.wasted_bytes_larger_pool);

	sysfs_remove_group(&pool->kobj, &cnss_pool_debug_attr_group);
	sysfs_remove_group(&pool->kobj, &cnss_pool_attr_group);
	kobject_del(&pool->kobj);
	kobject_put(&pool->kobj);
}

static inline void cnss_pool_update_stats(struct cnss_pool *pool,
					  size_t requested_size)
{
	pool->stats.alloc_count++;
	pool->stats.current_bytes_allocated += pool->size;
	if (pool->stats.current_bytes_allocated >
	    pool->stats.peak_bytes_allocated)
		pool->stats.peak_bytes_allocated =
			pool->stats.current_bytes_allocated;

	if (pool->size > requested_size) {
		pool->stats.larger_pool_alloc_count++;
		pool->stats.wasted_bytes_larger_pool +=
			(pool->size - requested_size);
	}
}

static inline void cnss_pool_update_free_stats(struct cnss_pool *pool)
{
	pool->stats.free_count++;
	pool->stats.current_bytes_allocated -= pool->size;
}

/**
 * cnss_pool_alloc_threshold() - Allocation threshold
 *
 * Minimum memory size to be part of cnss pool.
 *
 * Return: Size
 *
 */
static inline size_t cnss_pool_alloc_threshold(void)
{
	return WCNSS_PRE_ALLOC_GET_THRESHOLD;
}

#ifdef CONFIG_CNSS_PREALLOC_DEBUG_LEAK
static inline void cnss_stack_track_init(struct cnss_pool *cnss_pool)
{
	pr_info("Initializing stack track info\n");
	cnss_pool->alloc_info = kzalloc(cnss_pool->min *
						sizeof(struct cnss_alloc_info),
					GFP_KERNEL);
	if (!cnss_pool->alloc_info)
		pr_err("cnss_prealloc: failed to create alloc_info for %s\n",
		       cnss_pool->name);
}

static inline void cnss_stack_track_deinit(struct cnss_pool *cnss_pool)
{
	kfree(cnss_pool->alloc_info);
	cnss_pool->alloc_info = NULL;
}
#else
static inline void cnss_stack_track_init(struct cnss_pool *cnss_pool)
{
	cnss_pool->alloc_info = NULL;
}

static inline void cnss_stack_track_deinit(struct cnss_pool *cnss_pool)
{
}
#endif

/**
 * cnss_pool_int() - Initialize memory pools.
 *
 * Create cnss pools as configured by cnss_pools[]. It is the responsibility of
 * the caller to invoke cnss_pool_deinit() routine to clean it up. This
 * function needs to be called at early boot to preallocate minimum buffers in
 * the pool.
 *
 * Return: 0 - success, otherwise error code.
 *
 */
static void *cnss_mempool_alloc(gfp_t gfp_mask, void *pool_data)
{
	if (!mempool_initialization_done || !cnss_force_prealloc_pool)
		return mempool_alloc_slab(gfp_mask, pool_data);
	else
		return NULL;

}

static int cnss_pool_init(void)
{
	int i;

	for (i = 0; i < cnss_prealloc_pool_size; i++) {
		/* Create the slab cache */
		cnss_pools[i].cache =
			kmem_cache_create_usercopy(cnss_pools[i].name,
						   cnss_pools[i].size, 0,
						   SLAB_ACCOUNT, 0,
						   cnss_pools[i].size, NULL);
		if (!cnss_pools[i].cache) {
			pr_err("cnss_prealloc: cache %s failed\n",
			       cnss_pools[i].name);
			continue;
		}

		/* Create the pool and associate to slab cache */
		cnss_pools[i].mp =
		    mempool_create(cnss_pools[i].min, cnss_mempool_alloc,
				   mempool_free_slab, cnss_pools[i].cache);

		if (!cnss_pools[i].mp) {
			pr_err("cnss_prealloc: mempool %s failed\n",
			       cnss_pools[i].name);
			kmem_cache_destroy(cnss_pools[i].cache);
			cnss_pools[i].cache = NULL;
			continue;
		}

		cnss_pools[i].table_capacity = cnss_pools[i].min;
		cnss_pools[i].pool_ptrs = kzalloc(cnss_pools[i].min * sizeof(void *),
						  GFP_KERNEL);

		if (!cnss_pools[i].pool_ptrs) {
			pr_err("cnss_prealloc: failed to create mempool %s of min size %d * %zu\n",
			       cnss_pools[i].name, cnss_pools[i].min,
			       cnss_pools[i].size);
			kfree(cnss_pools[i].pool_ptrs);
			cnss_pools[i].pool_ptrs = NULL;
			WARN_ON(1);
		}

		/* Initialize sysfs for this pool if debug leak tracking is enabled */
		if (cnss_prealloc_sysfs_stats)
			cnss_pool_sysfs_init(&cnss_pools[i]);

		pr_info("cnss_prealloc: created mempool %s of min size %d * %zu\n",
			cnss_pools[i].name, cnss_pools[i].min,
			cnss_pools[i].size);

		cnss_stack_track_init(&cnss_pools[i]);
	}

	mempool_initialization_done = true;
	spin_lock_init(&pool_table_lock);

	return 0;
}

/**
 * cnss_pool_deinit() - Free memory pools.
 *
 * Free the memory pools and return resources back to the system. It warns
 * if there is any pending element in memory pool or cache.
 *
 */
static void cnss_pool_deinit(void)
{
	int i;

	if (!cnss_pools)
		return;

	for (i = 0; i < cnss_prealloc_pool_size; i++) {
		pr_info("cnss_prealloc: destroy mempool %s\n",
			cnss_pools[i].name);
		if (cnss_prealloc_sysfs_stats)
			cnss_pool_sysfs_exit(&cnss_pools[i]);
		mempool_destroy(cnss_pools[i].mp);
		kmem_cache_destroy(cnss_pools[i].cache);
		cnss_pools[i].mp = NULL;
		cnss_pools[i].cache = NULL;
		kfree(cnss_pools[i].pool_ptrs);
		cnss_pools[i].pool_ptrs = NULL;

		cnss_stack_track_deinit(&cnss_pools[i]);
	}

	mempool_initialization_done = false;
}

static void cnss_assign_prealloc_pool(unsigned long device_id)
{
	cnss_force_prealloc_pool = false;

	switch (device_id) {
	case ADRASTEA_DEVICE_ID:
		cnss_force_prealloc_pool = true;
		cnss_pools = cnss_pools_adrastea;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_adrastea);
		break;
	case WCN6750_DEVICE_ID:
		cnss_pools = cnss_pools_wcn6750;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_wcn6750);
		break;
	case WCN7750_DEVICE_ID:
		cnss_pools = cnss_pools_wcn7750;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_wcn7750);
		break;
	case WCN6450_DEVICE_ID:
		cnss_force_prealloc_pool = true;
		cnss_pools = cnss_pools_wcn6450;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_wcn6450);
		break;
	case FIG_DEVICE_ID:
		cnss_force_prealloc_pool = true;
		cnss_pools = cnss_pools_fig;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_fig);
		break;
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
	case KIWI_DEVICE_ID:
	default:
		cnss_pools = cnss_pools_default;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_default);
	}

	pr_info("cnss_prealloc: assign cnss pool for device id 0x%lx with force_prealloc:%s\n",
		device_id, cnss_force_prealloc_pool ? "enabled":"disabled");
}

void cnss_initialize_prealloc_pool(unsigned long device_id)
{
	cnss_assign_prealloc_pool(device_id);
	cnss_pool_init();
}
EXPORT_SYMBOL(cnss_initialize_prealloc_pool);

void cnss_deinitialize_prealloc_pool(void)
{
	cnss_pool_deinit();
}
EXPORT_SYMBOL(cnss_deinitialize_prealloc_pool);

/**
 * cnss_record_stack_trace() - Record stack trace for memory allocation
 * @alloc_info: Pointer to allocation info structure
 * @mem: Allocated memory pointer
 */
static inline
void cnss_record_stack_trace(struct cnss_alloc_info *alloc_info, void *mem,
			     const char *pool_name)
{
	unsigned long stack_addrs[CNSS_STACK_TRACE_DEPTH];
	unsigned int nr_entries;
	int i;

	if (!alloc_info)
		return;

	alloc_info->ptr = mem;
	alloc_info->timestamp = jiffies;
	alloc_info->pid = current->pid;
	strscpy(alloc_info->comm, current->comm, TASK_COMM_LEN);
	alloc_info->comm[TASK_COMM_LEN - 1] = '\0';

	/* First get the raw stack addresses */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
	nr_entries = stack_trace_save(stack_addrs, CNSS_STACK_TRACE_DEPTH, 1);
#else
	{
		struct stack_trace trace = {
			.entries = stack_addrs,
			.max_entries = CNSS_STACK_TRACE_DEPTH,
			.skip = 1,
		};
		save_stack_trace(&trace);
		nr_entries = trace.nr_entries;
	}
#endif

	alloc_info->nr_entries = nr_entries;

	/* Convert addresses to symbol names with offsets using sprint_symbol */
	for (i = 0; i < nr_entries; i++) {
		/* Use sprint_symbol which is exported for modules */
		int ret = sprint_symbol(alloc_info->stack_entries[i].symbol,
					stack_addrs[i]);
		if (ret < 0) {
			/* Fallback to raw address if symbol lookup fails */
			snprintf(alloc_info->stack_entries[i].symbol,
				 CNSS_SYMBOL_NAME_LEN, "0x%lx", stack_addrs[i]);
			alloc_info->stack_entries[i].offset = 0;
			alloc_info->stack_entries[i].size = 0;
		} else {
			/* sprint_symbol doesn't provide offset/size separately,
			 * but the symbol string contains the information
			 */
			alloc_info->stack_entries[i].offset = 0;
			alloc_info->stack_entries[i].size = 0;
		}
	}
}

/**
 * cnss_clear_stack_trace() - Clear stack trace for memory deallocation
 * @alloc_info: Pointer to allocation info structure
 */
static void cnss_clear_stack_trace(struct cnss_alloc_info *alloc_info,
				   const char *pool_name)
{
	if (!alloc_info)
		return;

	memset(alloc_info, 0, sizeof(*alloc_info));
}

/**
 * cnss_print_stack_trace() - Print stack trace for debugging
 * @alloc_info: Pointer to allocation info structure
 * @pool_name: Pool name for identification
 */
static inline
void cnss_print_stack_trace(struct cnss_alloc_info *alloc_info,
			    const char *pool_name)
{
	int i;
	unsigned long delta_jiffies;

	if (!alloc_info || !alloc_info->ptr)
		return;

	delta_jiffies = jiffies - alloc_info->timestamp;
	pr_info("cnss_prealloc: Memory leak detected in %s pool\n", pool_name);
	pr_info("  Pointer: %p, PID: %d, Comm: %s\n",
		alloc_info->ptr, alloc_info->pid, alloc_info->comm);
	pr_info("  Allocated %lu jiffies ago (%u ms)\n",
		delta_jiffies, jiffies_to_msecs(delta_jiffies));
	pr_info("  Stack trace (%u entries):\n", alloc_info->nr_entries);

	for (i = 0; i < alloc_info->nr_entries; i++)
		pr_info("    %s\n", alloc_info->stack_entries[i].symbol);
}

void wcnss_check_pool_lists(void)
{
	void **pool;
	struct cnss_alloc_info *alloc_info;
	int i;
	size_t ptr_idx;
	int count;
	int active_allocs = 0;

	pr_info("wcnss enter pool check\n");

	for (i = 0; i < cnss_prealloc_pool_size; i++) {
		pool = cnss_pools[i].pool_ptrs;
		alloc_info = cnss_pools[i].alloc_info;
		count = cnss_pools[i].table_capacity;
		pr_info("Max allocation #%d in %s pool:\n", count,
			cnss_pools[i].name);
		for (ptr_idx = 0; ptr_idx < count; ptr_idx++) {
			if (pool[ptr_idx]) {
				pr_err("%p not freed in %s pool at index %zu\n",
					pool[ptr_idx], cnss_pools[i].name,
					ptr_idx);

				/* Print stack trace if available */
				if (alloc_info &&
				    alloc_info[ptr_idx].ptr == pool[ptr_idx]) {
					active_allocs++;
					pr_info("Active allocation #%d in %s pool:\n",
						active_allocs,
						cnss_pools[i].name);
					cnss_print_stack_trace(
						&alloc_info[ptr_idx],
						cnss_pools[i].name);
				}

				CNSS_ASSERT(0);
			}
		}
	}

	if (active_allocs) {
		pr_info("cnss_prealloc: Total active allocations: %d\n",
			active_allocs);
		/* Assert independent of perf or debug build */
		BUG();
	}
}
EXPORT_SYMBOL(wcnss_check_pool_lists);

static int wcnss_find_pool_table_slot(int pool, void *mem, size_t requested_size)
{
	void **pool_table;
	struct cnss_alloc_info *alloc_info;
	size_t ptr_idx;
	int new_capacity;

	pool_table = cnss_pools[pool].pool_ptrs;
	alloc_info = cnss_pools[pool].alloc_info;

	for (ptr_idx = 0; ptr_idx < cnss_pools[pool].table_capacity; ptr_idx++) {
		if (!pool_table[ptr_idx]) {
			pool_table[ptr_idx] = mem;
			/* Record stack trace for this allocation */
			if (alloc_info) {
				alloc_info[ptr_idx].requested_size = requested_size;
				cnss_record_stack_trace(&alloc_info[ptr_idx],
							mem,
							cnss_pools[pool].name);
			}
			return ptr_idx;
		}
	}

	new_capacity = cnss_pools[pool].table_capacity + 1;

	cnss_pools[pool].pool_ptrs = krealloc(cnss_pools[pool].pool_ptrs,
					      new_capacity * sizeof(void *),
					      GFP_ATOMIC);

	if (!cnss_pools[pool].pool_ptrs) {
		pr_debug("%s pool is full, failed to increase table size to %d\n",
			 cnss_pools[pool].name, cnss_pools[pool].table_capacity);
		return -EPERM;
	}

	cnss_pools[pool].pool_ptrs[ptr_idx] = mem;

	if (alloc_info) {
		cnss_pools[pool].alloc_info = krealloc(
				cnss_pools[pool].alloc_info,
				new_capacity * sizeof(struct cnss_alloc_info),
				GFP_ATOMIC);
		if (cnss_pools[pool].alloc_info) {
			/* Initialize the new alloc_info slot */
			memset(&cnss_pools[pool].alloc_info[ptr_idx], 0,
			       sizeof(struct cnss_alloc_info));
			cnss_pools[pool].alloc_info[ptr_idx].requested_size = requested_size;
			/* Record stack trace for this allocation */
			cnss_record_stack_trace(
				&cnss_pools[pool].alloc_info[ptr_idx],
				mem, cnss_pools[pool].name);
		} else {
			pr_info("Failed to increase alloc_info size for %s\n",
				cnss_pools[pool].name);
		}
	}

	cnss_pools[pool].table_capacity += 1;

	pr_debug("%s pool is full, increasing table size to %d\n",
		 cnss_pools[pool].name, cnss_pools[pool].table_capacity);

	return ptr_idx;
}

static int wcnss_free_pool_table_slot(struct cnss_pool mempool, void *mem)
{
	void **pool_table;
	struct cnss_alloc_info *alloc_info;
	size_t ptr_idx;

	pool_table = mempool.pool_ptrs;
	alloc_info = mempool.alloc_info;

	for (ptr_idx = 0; ptr_idx < mempool.table_capacity; ptr_idx++) {
		if (pool_table[ptr_idx] == mem) {
			pool_table[ptr_idx] = NULL;
			/* Clear stack trace for this deallocation */
			if (alloc_info)
				cnss_clear_stack_trace(&alloc_info[ptr_idx],
						       mempool.name);
			return ptr_idx;
		}
	}

	pr_debug("wcnss prealloc put ptr %p not found in %s pool mem addr %p\n",
		 mem, mempool.name, mempool.pool_ptrs);

	return -EPERM;
}

/**
 * wcnss_prealloc_get() - Get preallocated memory from a pool
 * @size: Size to allocate
 *
 * Memory pool is chosen based on the size. If memory is not available in a
 * given pool it goes to next higher sized pool until it succeeds.
 *
 * Return: A void pointer to allocated memory
 */
void *wcnss_prealloc_get(size_t size)
{

	void *mem = NULL;
	gfp_t gfp_mask = __GFP_ZERO;
	unsigned long irq_flags;
	int i;
	int ret = 0;

	if (!cnss_pools || !mempool_initialization_done)
		return mem;

	if (in_interrupt() || !preemptible() || rcu_preempt_depth())
		gfp_mask |= GFP_ATOMIC;
	else {
		gfp_mask |= GFP_KERNEL;
		if (cnss_force_prealloc_pool)
			gfp_mask &= ~__GFP_DIRECT_RECLAIM;
	}

	if (size > cnss_pool_alloc_threshold()) {

		for (i = 0; i < cnss_prealloc_pool_size; i++) {
			if (cnss_pools[i].size >= size && cnss_pools[i].mp) {
				if (!cnss_pools[i].pool_ptrs) {
					pr_err("%s mempool table is null\n",
					       cnss_pools[i].name);
					mem = NULL;
					break;
				}
				mem = mempool_alloc(cnss_pools[i].mp, gfp_mask);
				if (mem) {
					spin_lock_irqsave(&pool_table_lock,
							  irq_flags);
					ret = wcnss_find_pool_table_slot(i, mem, size);
					if (ret >= 0 && cnss_prealloc_sysfs_stats)
						cnss_pool_update_stats(&cnss_pools[i], size);

					spin_unlock_irqrestore(&pool_table_lock,
							       irq_flags);
					break;
				}
			}
		}
	}
	if (ret < 0) {
		mempool_free(mem, cnss_pools[i].mp);
		mem = NULL;
	}

	if (!mem && size > cnss_pool_alloc_threshold()) {
		pr_err("cnss_prealloc: not available for size %zu, flag %x\n",
		       size, gfp_mask);
	}

	return mem;
}
EXPORT_SYMBOL(wcnss_prealloc_get);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0))
/**
 * wcnss_prealloc_put() - Relase allocated memory
 * @mem: Allocated memory
 *
 * Free the memory got by wcnss_prealloc_get() to slab or pool reserve if memory
 * pool doesn't have enough elements.
 *
 * Return: 1 - success
 *         0 - fail
 */
int wcnss_prealloc_put(void *mem)
{
	int i;
	int ret;
	unsigned long irq_flags;

	if (!mem || !cnss_pools || !mempool_initialization_done)
		return 0;

	for (i = 0; i < cnss_prealloc_pool_size; i++) {
		if (cnss_pools[i].mp) {
			if (!cnss_pools[i].pool_ptrs) {
				pr_err("%s mempool table is null\n",
				       cnss_pools[i].name);
				break;
			}
			spin_lock_irqsave(&pool_table_lock, irq_flags);
			ret = wcnss_free_pool_table_slot(cnss_pools[i],
							 mem);
			if (ret >= 0 && cnss_prealloc_sysfs_stats)
				cnss_pool_update_free_stats(&cnss_pools[i]);

			spin_unlock_irqrestore(&pool_table_lock,
					       irq_flags);

			if (ret >= 0) {
				mempool_free(mem, cnss_pools[i].mp);
				return 1;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(wcnss_prealloc_put);
#else
static int cnss_pool_get_index(void *mem)
{
	struct page *page;
	struct kmem_cache *cache;
	int i;

	if (!virt_addr_valid(mem))
		return -EINVAL;

	/* mem -> page -> cache */
	page = virt_to_head_page(mem);
	if (!page)
		return -ENOENT;

	cache = page->slab_cache;
	if (!cache)
		return -ENOENT;

	/* Check if memory belongs to a pool */
	for (i = 0; i < cnss_prealloc_pool_size; i++) {
		if (cnss_pools[i].cache == cache)
			return i;
	}

	return -ENOENT;
}

/**
 * wcnss_prealloc_put() - Relase allocated memory
 * @mem: Allocated memory
 *
 * Free the memory got by wcnss_prealloc_get() to slab or pool reserve if memory
 * pool doesn't have enough elements.
 *
 * Return: 1 - success
 *         0 - fail
 */
int wcnss_prealloc_put(void *mem)
{
	int i;
	int ret;
	unsigned long irq_flags;

	if (!mem || !cnss_pools || !mempool_initialization_done)
		return 0;

	i = cnss_pool_get_index(mem);
	if (i >= 0 && i < cnss_prealloc_pool_size && cnss_pools[i].mp) {
		if (!cnss_pools[i].pool_ptrs) {
			pr_err("%s mempool table is null\n",
			       cnss_pools[i].name);
			return 0;
		}
		spin_lock_irqsave(&pool_table_lock, irq_flags);
		ret = wcnss_free_pool_table_slot(cnss_pools[i], mem);
		if (ret >= 0 && cnss_prealloc_sysfs_stats)
			cnss_pool_update_free_stats(&cnss_pools[i]);

		spin_unlock_irqrestore(&pool_table_lock, irq_flags);
		if (ret >= 0) {
			mempool_free(mem, cnss_pools[i].mp);
			return 1;
		}
	}

	return 0;
}
EXPORT_SYMBOL(wcnss_prealloc_put);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)) */

/* Not implemented. Make use of Linux SLAB features. */
void wcnss_prealloc_check_memory_leak(void) {}
EXPORT_SYMBOL(wcnss_prealloc_check_memory_leak);

/* Not implemented. Make use of Linux SLAB features. */
int wcnss_pre_alloc_reset(void) { return -EOPNOTSUPP; }
EXPORT_SYMBOL(wcnss_pre_alloc_reset);

/**
 * cnss_prealloc_is_valid_dt_node_found - Check if valid device tree node
 *                                        present
 *
 * Valid device tree node means a node with "qcom,wlan" property present
 * and "status" property not disabled.
 *
 * Return: true if valid device tree node found, false if not found
 */
static bool cnss_prealloc_is_valid_dt_node_found(void)
{
	struct device_node *dn = NULL;

	for_each_node_with_property(dn, "qcom,wlan") {
		if (of_device_is_available(dn))
			break;
	}

	if (dn)
		return true;

	return false;
}

static int __init cnss_prealloc_init(void)
{
	if (!cnss_prealloc_is_valid_dt_node_found())
		return -ENODEV;

	cnss_prealloc_sysfs_init();
	return 0;
}

static void __exit cnss_prealloc_exit(void)
{
	cnss_prealloc_sysfs_exit();
}

module_init(cnss_prealloc_init);
module_exit(cnss_prealloc_exit);

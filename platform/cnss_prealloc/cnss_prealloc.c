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
#include "cnss_common.h"
#ifdef CONFIG_CNSS_OUT_OF_TREE
#include "cnss_prealloc.h"
#else
#include <net/cnss_prealloc.h>
#endif

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CNSS prealloc driver");

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
#define CNSS_SYMBOL_NAME_LEN 128

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
	{128 * 1024, 10, "cnss-pool-128k", NULL, NULL, NULL},
	{256 * 1024, 2, "cnss-pool-256k", NULL, NULL, NULL},
};

static struct cnss_pool cnss_pools_adrastea[] = {
	{16 * 1024, 10, "cnss-pool-16k", NULL, NULL, NULL},
	{32 * 1024, 8, "cnss-pool-32k", NULL, NULL, NULL},
	{64 * 1024, 4, "cnss-pool-64k", NULL, NULL, NULL},
	{128 * 1024, 2, "cnss-pool-128k", NULL, NULL, NULL},
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

struct cnss_pool *cnss_pools;
unsigned int cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_default);
spinlock_t pool_table_lock;
bool mempool_initialization_done;

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
		    mempool_create(cnss_pools[i].min, mempool_alloc_slab,
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
	pr_info("cnss_prealloc: assign cnss pool for device id 0x%lx", device_id);

	switch (device_id) {
	case ADRASTEA_DEVICE_ID:
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
	case QCA6390_DEVICE_ID:
	case QCA6490_DEVICE_ID:
	case MANGO_DEVICE_ID:
	case PEACH_DEVICE_ID:
	case KIWI_DEVICE_ID:
	case FIG_DEVICE_ID:
	default:
		cnss_pools = cnss_pools_default;
		cnss_prealloc_pool_size = ARRAY_SIZE(cnss_pools_default);
	}
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
void cnss_record_stack_trace(struct cnss_alloc_info *alloc_info, void *mem)
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
static void cnss_clear_stack_trace(struct cnss_alloc_info *alloc_info)
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

static int wcnss_find_pool_table_slot(int pool, void *mem)
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
				cnss_record_stack_trace(&alloc_info[ptr_idx],
							mem);
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
			/* Record stack trace for this allocation */
			cnss_record_stack_trace(
				&cnss_pools[pool].alloc_info[ptr_idx],
				mem);
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
				cnss_clear_stack_trace(&alloc_info[ptr_idx]);
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
	else
		gfp_mask |= GFP_KERNEL;

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
					ret = wcnss_find_pool_table_slot(i, mem);
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

	return 0;
}

static void __exit cnss_prealloc_exit(void)
{
	return;
}

module_init(cnss_prealloc_init);
module_exit(cnss_prealloc_exit);

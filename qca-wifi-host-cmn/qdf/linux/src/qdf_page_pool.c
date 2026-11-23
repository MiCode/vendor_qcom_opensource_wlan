/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <qdf_page_pool.h>
#include <qdf_nbuf.h>
#include <linux/ptr_ring.h>
#include <qdf_mem.h>

#define QDF_PP_MAX_POOL 16

/**
 * struct qdf_pp_tracker - Page pool tracker structure
 * @created: Pool creation status
 * @buff_count: Atomic counter for in-flight buffers
 * @pp: Page pool pointer
 */
struct qdf_pp_tracker {
	bool created;
	qdf_atomic_t buff_count;
	__qdf_page_pool_t pp;
};

/* Global page pool tracking array */
static struct qdf_pp_tracker g_qdf_pp_tracker[QDF_PP_MAX_POOL];

/**
 * qdf_page_pool_track_register() - Register page pool for tracking
 * @pp: Page pool pointer
 * @rx_pp_track_id: Pointer to store the track id assigned by tracker
 *
 * Return: Pool index on success, negative value on failure
 */
static inline int qdf_page_pool_track_register(__qdf_page_pool_t pp,
					       int *rx_pp_track_id)
{
	int idx;

	if (qdf_unlikely(!pp || !rx_pp_track_id))
		return -QDF_STATUS_E_INVAL;

	/* Start from idx 1 since 0 is also valid for pp_track_id set in nbuf */
	for (idx = 1; idx < QDF_PP_MAX_POOL; idx++) {
		if (!g_qdf_pp_tracker[idx].created) {
			g_qdf_pp_tracker[idx].pp = pp;
			g_qdf_pp_tracker[idx].created = true;
			__qdf_atomic_init(&g_qdf_pp_tracker[idx].buff_count);
			qdf_nofl_info("Page pool tracker registered: track_id=%d, pp=%pK",
				      idx, pp);
			*rx_pp_track_id = idx;
			return QDF_STATUS_SUCCESS;
		}
	}
	*rx_pp_track_id = 0;
	qdf_rl_nofl_err("No slot available for page pool tracker registration");
	return -QDF_STATUS_E_FAILURE;
}

/**
 * qdf_page_pool_find_track_idx() - Find track id for a given page pool
 * @pp: Page pool pointer
 *
 * Return: Pool index on success, -1 on failure
 */
static inline int qdf_page_pool_find_track_idx(__qdf_page_pool_t pp)
{
	int track_id;

	if (qdf_unlikely(!pp))
		return -QDF_STATUS_E_INVAL;

	for (track_id = 0; track_id < QDF_PP_MAX_POOL; track_id++) {
		if (g_qdf_pp_tracker[track_id].created &&
		    g_qdf_pp_tracker[track_id].pp == pp)
			return track_id;
	}

	return -QDF_STATUS_E_FAILURE;
}

/**
 * qdf_page_pool_track_unregister() - Unregister page pool from tracking
 * @pp: Page pool pointer
 *
 * Return: None
 */
static inline void qdf_page_pool_track_unregister(__qdf_page_pool_t pp)
{
	int buff_count;
	int idx;

	idx = qdf_page_pool_find_track_idx(pp);

	if (idx < 0)
		return;

	buff_count = __qdf_atomic_read(&g_qdf_pp_tracker[idx].buff_count);

	if (qdf_likely(g_qdf_pp_tracker[idx].created)) {
		qdf_nofl_info("Page pool tracker unregistering: track_id=%d, pp=%pK, buff_count=%d",
			      idx, g_qdf_pp_tracker[idx].pp,
			      buff_count);
		g_qdf_pp_tracker[idx].created = false;
		g_qdf_pp_tracker[idx].pp = NULL;
		__qdf_atomic_set(&g_qdf_pp_tracker[idx].buff_count, 0);
	}
}

bool __qdf_is_pp_nbuf(struct sk_buff *skb)
{
	return !!skb->pp_recycle;
}

struct page *__qdf_page_pool_alloc_page(qdf_page_pool_t pp)
{
	return page_pool_dev_alloc_pages(pp);
}

dma_addr_t __qdf_page_pool_get_dma_addr(struct page *page)
{
	return page_pool_get_dma_addr(page);
}

bool __qdf_page_pool_full_bh(__qdf_page_pool_t pp)
{
	int i;
	int count = 0;

	if (!pp->alloc.count)
		return ptr_ring_full_bh(&pp->ring);

	for (i = 0; i < pp->ring.size; i++) {
		if (pp->ring.queue[i])
			count++;
	}

	return (pp->ring.size - count == pp->alloc.count);
}

bool __qdf_page_pool_empty(__qdf_page_pool_t pp)
{
	return !pp->alloc.count && ptr_ring_empty(&pp->ring);
}

struct page *__qdf_page_pool_alloc_frag(__qdf_page_pool_t pp, uint32_t *offset,
					size_t size)
{
	return page_pool_dev_alloc_frag(pp, offset, size);
}

void __qdf_page_pool_put_page(__qdf_page_pool_t pp, struct page *page,
			      bool direct_recycle)
{
	return page_pool_put_full_page(pp, page, direct_recycle);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0))
static void set_page_param_frag_flag(struct page_pool_params *pp_params)
{
	pp_params->flags |= PP_FLAG_PAGE_FRAG;
}
#else
static void set_page_param_frag_flag(struct page_pool_params *pp_params)
{
}
#endif

__qdf_page_pool_t __qdf_page_pool_create(qdf_device_t osdev, size_t pool_size,
					 size_t pp_page_size, qdf_dma_dir_t dir,
					 int *rx_pp_track_id)
{
	struct page_pool_params pp_params = {0};
	struct page_pool *pp;
	int ret;

	pp_params.order = get_order(pp_page_size);
	pp_params.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
	pp_params.nid = NUMA_NO_NODE,
	pp_params.dev = osdev->dev,
	pp_params.dma_dir = __qdf_dma_dir_to_os(dir),
	pp_params.offset = 0,
	pp_params.max_len = pp_page_size;
	pp_params.pool_size = pool_size;
	set_page_param_frag_flag(&pp_params);

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp)) {
		ret = PTR_ERR(pp);
		qdf_rl_nofl_err("Failed to create page pool: %d", ret);
		return NULL;
	}
	if (rx_pp_track_id) {
		ret = qdf_page_pool_track_register(pp, rx_pp_track_id);
		if (ret < 0) {
			page_pool_destroy(pp);
			return NULL;
		}
	}

	return pp;
}

void __qdf_page_pool_destroy(__qdf_page_pool_t pp)
{
	qdf_page_pool_track_unregister(pp);

	return page_pool_destroy(pp);
}

void __qdf_page_pool_inc_buf_count(__qdf_nbuf_t nbuf)
{
	int track_id;

	track_id = qdf_nbuf_rx_pp_track_id_get(nbuf);

	__qdf_atomic_inc(&g_qdf_pp_tracker[track_id].buff_count);
}

void __qdf_page_pool_dec_buf_count(__qdf_nbuf_t nbuf)
{
	int track_id;

	track_id = qdf_nbuf_rx_pp_track_id_get(nbuf);

	__qdf_atomic_dec(&g_qdf_pp_tracker[track_id].buff_count);
}

bool __qdf_page_pool_check_inflight_buffers(__qdf_page_pool_t pp, int rx_pp_idx)
{
	int count;

	if (qdf_unlikely((!pp || rx_pp_idx >= QDF_PP_MAX_POOL)))
		return false;

	/* Verify that the pp in tracker matches the pp passed */
	if (qdf_unlikely(g_qdf_pp_tracker[rx_pp_idx].pp != pp))
		return false;

	count = __qdf_atomic_read(&g_qdf_pp_tracker[rx_pp_idx].buff_count);
	return (count != 0);
}

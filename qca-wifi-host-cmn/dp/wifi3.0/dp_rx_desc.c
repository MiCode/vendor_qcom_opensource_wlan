/*
 * Copyright (c) 2016-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include "dp_types.h"
#include "dp_rx.h"
#include "dp_ipa.h"
#include <qdf_module.h>
#ifdef WLAN_FEATURE_OSRTP
#include "xdp_sock_drv.h"
#endif

#ifdef RX_DESC_MULTI_PAGE_ALLOC
A_COMPILE_TIME_ASSERT(cookie_size_check,
		      (DP_BLOCKMEM_SIZE /
		       sizeof(union dp_rx_desc_list_elem_t))
		      <= (1 << DP_RX_DESC_PAGE_ID_SHIFT));

QDF_STATUS dp_rx_desc_pool_is_allocated(struct rx_desc_pool *rx_desc_pool)
{
	if (!rx_desc_pool->desc_pages.num_pages) {
		dp_err("Multi page alloc fail, size=%d, elem=%d",
		       rx_desc_pool->elem_size, rx_desc_pool->pool_size);
		return QDF_STATUS_E_NOMEM;
	}
	return QDF_STATUS_SUCCESS;
}

qdf_export_symbol(dp_rx_desc_pool_is_allocated);

QDF_STATUS dp_rx_desc_pool_alloc(struct dp_soc *soc,
				 uint32_t num_elem,
				 struct rx_desc_pool *rx_desc_pool)
{
	uint32_t desc_size;
	union dp_rx_desc_list_elem_t *rx_desc_elem;

	desc_size = sizeof(*rx_desc_elem);
	rx_desc_pool->elem_size = desc_size;
	rx_desc_pool->desc_pages.page_size = DP_BLOCKMEM_SIZE;
	dp_desc_multi_pages_mem_alloc(soc, rx_desc_pool->desc_type,
				      &rx_desc_pool->desc_pages,
				      desc_size, num_elem, 0, true);
	if (!rx_desc_pool->desc_pages.num_pages) {
		qdf_err("Multi page alloc fail,size=%d, elem=%d",
			desc_size, num_elem);
		return QDF_STATUS_E_NOMEM;
	}

	if (qdf_mem_multi_page_link(soc->osdev,
				    &rx_desc_pool->desc_pages,
				    desc_size, num_elem, true)) {
		qdf_err("overflow num link,size=%d, elem=%d",
			desc_size, num_elem);
		goto free_rx_desc_pool;
	}
	return QDF_STATUS_SUCCESS;

free_rx_desc_pool:
	dp_rx_desc_pool_free(soc, rx_desc_pool);

	return QDF_STATUS_E_FAULT;
}

qdf_export_symbol(dp_rx_desc_pool_alloc);

QDF_STATUS dp_rx_desc_pool_init_generic(struct dp_soc *soc,
				  struct rx_desc_pool *rx_desc_pool,
				  uint32_t pool_id)
{
	uint32_t id, page_id, offset, num_desc_per_page;
	uint32_t count = 0;
	union dp_rx_desc_list_elem_t *rx_desc_elem;

	num_desc_per_page = rx_desc_pool->desc_pages.num_element_per_page;

	rx_desc_elem = rx_desc_pool->freelist;
	while (rx_desc_elem) {
		page_id = count / num_desc_per_page;
		offset = count % num_desc_per_page;
		/*
		 * Below cookie size is from REO destination ring
		 * reo_destination_ring -> buffer_addr_info -> sw_buffer_cookie
		 * cookie size = 21 bits
		 * 8 bits - offset
		 * 8 bits - page ID
		 * 4 bits - pool ID
		 */
		id = ((pool_id << DP_RX_DESC_POOL_ID_SHIFT) |
		      (page_id << DP_RX_DESC_PAGE_ID_SHIFT) |
		      offset);
		rx_desc_elem->rx_desc.cookie = id;
		rx_desc_elem->rx_desc.pool_id = pool_id;
		rx_desc_elem->rx_desc.in_use = 0;
		rx_desc_elem = rx_desc_elem->next;
		count++;
	}
	return QDF_STATUS_SUCCESS;
}

void dp_rx_desc_pool_init(struct dp_soc *soc, uint32_t pool_id,
			  uint32_t pool_size, struct rx_desc_pool *rx_desc_pool)
{
	QDF_STATUS status;

	/* Initialize the lock */
	qdf_spinlock_create(&rx_desc_pool->lock);

	qdf_spin_lock_bh(&rx_desc_pool->lock);
	rx_desc_pool->pool_size = pool_size;

	rx_desc_pool->freelist = (union dp_rx_desc_list_elem_t *)
				  *rx_desc_pool->desc_pages.cacheable_pages;

	status = soc->arch_ops.dp_rx_desc_pool_init(soc, rx_desc_pool,
						    pool_id);
	if (!QDF_IS_STATUS_SUCCESS(status))
		dp_err("RX desc pool initialization failed");

	qdf_spin_unlock_bh(&rx_desc_pool->lock);
}

qdf_export_symbol(dp_rx_desc_pool_init);

union dp_rx_desc_list_elem_t *dp_rx_desc_find(uint16_t page_id, uint16_t offset,
					      struct rx_desc_pool *rx_desc_pool)
{
	return rx_desc_pool->desc_pages.cacheable_pages[page_id] +
		rx_desc_pool->elem_size * offset;
}

static QDF_STATUS dp_rx_desc_nbuf_collect(struct dp_soc *soc,
					  struct rx_desc_pool *rx_desc_pool,
					  qdf_nbuf_t *nbuf_unmap_list,
					  qdf_nbuf_t *nbuf_free_list
#ifdef WLAN_FEATURE_OSRTP
					  , qdf_xbuf_t *xbuf_free_list
#endif
					  )
{
	uint32_t i, num_desc, page_id, offset, num_desc_per_page;
	union dp_rx_desc_list_elem_t *rx_desc_elem;
	struct dp_rx_desc *rx_desc;

	if (qdf_unlikely(!(rx_desc_pool->desc_pages.cacheable_pages))) {
		qdf_err("No pages found on this desc pool");
		return QDF_STATUS_E_INVAL;
	}
	num_desc = rx_desc_pool->pool_size;
	num_desc_per_page = rx_desc_pool->desc_pages.num_element_per_page;
	for (i = 0; i < num_desc; i++) {
		page_id = i / num_desc_per_page;
		offset = i % num_desc_per_page;
		rx_desc_elem = dp_rx_desc_find(page_id, offset, rx_desc_pool);
		rx_desc = &rx_desc_elem->rx_desc;
		dp_rx_desc_free_dbg_info(rx_desc);
		if (rx_desc->in_use) {
#ifdef WLAN_FEATURE_OSRTP
			if (rx_desc->xbuf) {
				DP_RX_XBUF_HEAD_APPEND(*xbuf_free_list, rx_desc->xbuf);
				DP_RX_HEAD_APPEND(*nbuf_free_list, rx_desc->nbuf);
			} else 
#endif
			if (!rx_desc->unmapped) {
				DP_RX_HEAD_APPEND(*nbuf_unmap_list,
						  rx_desc->nbuf);
				rx_desc->unmapped = 1;
			} else {
				DP_RX_HEAD_APPEND(*nbuf_free_list,
						  rx_desc->nbuf);
			}
		}
	}
	return QDF_STATUS_SUCCESS;
}

static void dp_rx_desc_nbuf_cleanup(struct dp_soc *soc,
				    qdf_nbuf_t nbuf_unmap_list,
				    qdf_nbuf_t nbuf_free_list,
#ifdef WLAN_FEATURE_OSRTP
				    qdf_xbuf_t xbuf_free_list,
#endif
				    uint16_t buf_size,
				    bool is_mon_pool)
{
	qdf_nbuf_t nbuf = nbuf_unmap_list;
	qdf_nbuf_t next;
#ifdef WLAN_FEATURE_OSRTP
	qdf_xbuf_t xbuf = xbuf_free_list;
	qdf_xbuf_t xnext;

	while (xbuf) {
		xnext = xbuf->next;
		qdf_xbuf_free(xbuf, true);
		xbuf = xnext;
	}
#endif

	while (nbuf) {
		next = nbuf->next;

		if (!is_mon_pool)
			dp_audio_smmu_unmap(soc->osdev,
					    QDF_NBUF_CB_PADDR(nbuf),
					    buf_size);

		if (qdf_atomic_read(&soc->ipa_mapped)) {
			if (dp_ipa_handle_rx_buf_smmu_mapping(
							soc, nbuf, buf_size,
							false, __func__,
							__LINE__))
				dp_info_rl("Unable to unmap nbuf: %pK", nbuf);
		}
		qdf_nbuf_unmap_nbytes_single(soc->osdev, nbuf,
					     QDF_DMA_BIDIRECTIONAL, buf_size);
		dp_rx_nbuf_free(nbuf);
		nbuf = next;
	}

	nbuf = nbuf_free_list;
	while (nbuf) {
		next = nbuf->next;
		dp_rx_nbuf_free(nbuf);
		nbuf = next;
	}
}

void dp_rx_desc_nbuf_and_pool_free(struct dp_soc *soc, uint32_t pool_id,
				   struct rx_desc_pool *rx_desc_pool)
{
	qdf_nbuf_t nbuf_unmap_list = NULL;
	qdf_nbuf_t nbuf_free_list = NULL;
#ifdef WLAN_FEATURE_OSRTP
	qdf_xbuf_t xbuf_free_list = NULL;
#endif

	qdf_spin_lock_bh(&rx_desc_pool->lock);
#ifdef WLAN_FEATURE_OSRTP
	dp_rx_desc_nbuf_collect(soc, rx_desc_pool,
				&nbuf_unmap_list, &nbuf_free_list, &xbuf_free_list);
#else
	dp_rx_desc_nbuf_collect(soc, rx_desc_pool,
				&nbuf_unmap_list, &nbuf_free_list);
#endif
	qdf_spin_unlock_bh(&rx_desc_pool->lock);
#ifdef WLAN_FEATURE_OSRTP
	dp_rx_desc_nbuf_cleanup(soc, nbuf_unmap_list, nbuf_free_list, xbuf_free_list,
				rx_desc_pool->buf_size, false);
#else
	dp_rx_desc_nbuf_cleanup(soc, nbuf_unmap_list, nbuf_free_list,
				rx_desc_pool->buf_size, false);
#endif
	qdf_spinlock_destroy(&rx_desc_pool->lock);
}

void dp_rx_desc_nbuf_free(struct dp_soc *soc,
			  struct rx_desc_pool *rx_desc_pool,
			  bool is_mon_pool)
{
	qdf_nbuf_t nbuf_unmap_list = NULL;
	qdf_nbuf_t nbuf_free_list = NULL;
#ifdef WLAN_FEATURE_OSRTP
	qdf_xbuf_t xbuf_free_list = NULL;
#endif
	qdf_spin_lock_bh(&rx_desc_pool->lock);
#ifdef WLAN_FEATURE_OSRTP
	dp_rx_desc_nbuf_collect(soc, rx_desc_pool,
				&nbuf_unmap_list, &nbuf_free_list, &xbuf_free_list);
#else
	dp_rx_desc_nbuf_collect(soc, rx_desc_pool,
				&nbuf_unmap_list, &nbuf_free_list);
#endif
	qdf_spin_unlock_bh(&rx_desc_pool->lock);
#ifdef WLAN_FEATURE_OSRTP
	dp_rx_desc_nbuf_cleanup(soc, nbuf_unmap_list, nbuf_free_list, xbuf_free_list,
				rx_desc_pool->buf_size, is_mon_pool);
#else
	dp_rx_desc_nbuf_cleanup(soc, nbuf_unmap_list, nbuf_free_list,
				rx_desc_pool->buf_size, is_mon_pool);
#endif
}

qdf_export_symbol(dp_rx_desc_nbuf_free);

void dp_rx_desc_pool_free(struct dp_soc *soc,
			  struct rx_desc_pool *rx_desc_pool)
{
	if (qdf_unlikely(!(rx_desc_pool->desc_pages.cacheable_pages)))
		return;

	dp_desc_multi_pages_mem_free(soc, rx_desc_pool->desc_type,
				     &rx_desc_pool->desc_pages, 0, true);
}

qdf_export_symbol(dp_rx_desc_pool_free);

void dp_rx_desc_pool_deinit(struct dp_soc *soc,
			    struct rx_desc_pool *rx_desc_pool,
			    uint32_t pool_id)
{
	qdf_spin_lock_bh(&rx_desc_pool->lock);

	rx_desc_pool->freelist = NULL;
	rx_desc_pool->pool_size = 0;

	/* Deinitialize rx mon desr frag flag */
	rx_desc_pool->rx_mon_dest_frag_enable = false;

	soc->arch_ops.dp_rx_desc_pool_deinit(soc, rx_desc_pool, pool_id);

	qdf_spin_unlock_bh(&rx_desc_pool->lock);
	qdf_spinlock_destroy(&rx_desc_pool->lock);
}

qdf_export_symbol(dp_rx_desc_pool_deinit);
#else
QDF_STATUS dp_rx_desc_pool_is_allocated(struct rx_desc_pool *rx_desc_pool)
{
	if (!rx_desc_pool->array) {
		dp_err("nss-wifi<4> skip Rx refil");
		return QDF_STATUS_E_NOMEM;
	}
	return QDF_STATUS_SUCCESS;
}

qdf_export_symbol(dp_rx_desc_pool_is_allocated);

QDF_STATUS dp_rx_desc_pool_alloc(struct dp_soc *soc,
				 uint32_t pool_size,
				 struct rx_desc_pool *rx_desc_pool)
{
	rx_desc_pool->array = qdf_mem_common_alloc(pool_size *
				     sizeof(union dp_rx_desc_list_elem_t));

	if (!(rx_desc_pool->array)) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "RX Desc Pool allocation failed");
		return QDF_STATUS_E_NOMEM;
	}
	return QDF_STATUS_SUCCESS;
}

qdf_export_symbol(dp_rx_desc_pool_alloc);

QDF_STATUS dp_rx_desc_pool_init_generic(struct dp_soc *soc,
				  struct rx_desc_pool *rx_desc_pool,
				  uint32_t pool_id)
{
	int i;

	for (i = 0; i <= rx_desc_pool->pool_size - 1; i++) {
		if (i == rx_desc_pool->pool_size - 1)
			rx_desc_pool->array[i].next = NULL;
		else
			rx_desc_pool->array[i].next =
				&rx_desc_pool->array[i + 1];
		rx_desc_pool->array[i].rx_desc.cookie = i | (pool_id << 18);
		rx_desc_pool->array[i].rx_desc.pool_id = pool_id;
		rx_desc_pool->array[i].rx_desc.in_use = 0;
	}
	return QDF_STATUS_SUCCESS;
}

void dp_rx_desc_pool_init(struct dp_soc *soc, uint32_t pool_id,
			  uint32_t pool_size, struct rx_desc_pool *rx_desc_pool)
{
	QDF_STATUS status;

	/* Initialize the lock */
	qdf_spinlock_create(&rx_desc_pool->lock);

	qdf_spin_lock_bh(&rx_desc_pool->lock);
	rx_desc_pool->pool_size = pool_size;

	/* link SW rx descs into a freelist */
	rx_desc_pool->freelist = &rx_desc_pool->array[0];
	qdf_mem_zero(rx_desc_pool->freelist, rx_desc_pool->pool_size);

	status = soc->arch_ops.dp_rx_desc_pool_init(soc, rx_desc_pool,
						    pool_id);
	if (!QDF_IS_STATUS_SUCCESS(status))
		dp_err("RX desc pool initialization failed");

	qdf_spin_unlock_bh(&rx_desc_pool->lock);
}

qdf_export_symbol(dp_rx_desc_pool_init);

#ifdef WLAN_SUPPORT_PPEDS
static inline
qdf_nbuf_t dp_rx_desc_get_nbuf(struct rx_desc_pool *rx_desc_pool, int i)
{
	if (rx_desc_pool->array[i].rx_desc.has_reuse_nbuf)
		return rx_desc_pool->array[i].rx_desc.reuse_nbuf;
	else
		return rx_desc_pool->array[i].rx_desc.nbuf;
}
#else
static inline
qdf_nbuf_t dp_rx_desc_get_nbuf(struct rx_desc_pool *rx_desc_pool, int i)
{
	return rx_desc_pool->array[i].rx_desc.nbuf;
}
#endif

void dp_rx_desc_nbuf_and_pool_free(struct dp_soc *soc, uint32_t pool_id,
				   struct rx_desc_pool *rx_desc_pool)
{
	qdf_nbuf_t nbuf;
	int i;

	qdf_spin_lock_bh(&rx_desc_pool->lock);
	for (i = 0; i < rx_desc_pool->pool_size; i++) {
		if (rx_desc_pool->array[i].rx_desc.in_use) {
			nbuf = dp_rx_desc_get_nbuf(rx_desc_pool, i);

			if (!(rx_desc_pool->array[i].rx_desc.unmapped)) {
				dp_rx_nbuf_unmap_pool(soc, rx_desc_pool, nbuf);
				rx_desc_pool->array[i].rx_desc.unmapped = 1;
			}
			dp_rx_nbuf_free(nbuf);
		}
	}
	qdf_mem_common_free(rx_desc_pool->array);
	qdf_spin_unlock_bh(&rx_desc_pool->lock);
	qdf_spinlock_destroy(&rx_desc_pool->lock);
}

void dp_rx_desc_nbuf_free(struct dp_soc *soc,
			  struct rx_desc_pool *rx_desc_pool,
			  bool is_mon_pool)
{
	qdf_nbuf_t nbuf;
#ifdef WLAN_FEATURE_OSRTP
	qdf_xbuf_t xbuf;
#endif
	int i;

	qdf_spin_lock_bh(&rx_desc_pool->lock);
	for (i = 0; i < rx_desc_pool->pool_size; i++) {
		dp_rx_desc_free_dbg_info(&rx_desc_pool->array[i].rx_desc);
		if (rx_desc_pool->array[i].rx_desc.in_use) {
			nbuf = dp_rx_desc_get_nbuf(rx_desc_pool, i);
#ifdef WLAN_FEATURE_OSRTP
			xbuf = rx_desc_pool->array[i].rx_desc.xbuf;
#endif

			if (!(rx_desc_pool->array[i].rx_desc.unmapped)) {
#ifdef WLAN_FEATURE_OSRTP
				if (xbuf)
					qdf_xbuf_unmap_nbytes_single(soc->osdev, xbuf, QDF_DMA_FROM_DEVICE, rx_desc_pool->buf_size);
				else
#endif
				dp_rx_nbuf_unmap_pool(soc, rx_desc_pool, nbuf);
				rx_desc_pool->array[i].rx_desc.unmapped = 1;
			}
#ifdef WLAN_FEATURE_OSRTP
			qdf_xbuf_free(xbuf, true);
#endif
			dp_rx_nbuf_free(nbuf);
		}
	}
	qdf_spin_unlock_bh(&rx_desc_pool->lock);
}

qdf_export_symbol(dp_rx_desc_nbuf_free);

#ifdef DP_RX_MON_MEM_FRAG
void dp_rx_desc_frag_free(struct dp_soc *soc,
			  struct rx_desc_pool *rx_desc_pool)
{
	qdf_dma_addr_t paddr;
	qdf_frag_t vaddr;
	int i;

	qdf_spin_lock_bh(&rx_desc_pool->lock);
	for (i = 0; i < rx_desc_pool->pool_size; i++) {
		if (rx_desc_pool->array[i].rx_desc.in_use) {
			paddr = rx_desc_pool->array[i].rx_desc.paddr_buf_start;
			vaddr = rx_desc_pool->array[i].rx_desc.rx_buf_start;

			dp_rx_desc_free_dbg_info(&rx_desc_pool->array[i].rx_desc);
			if (!(rx_desc_pool->array[i].rx_desc.unmapped)) {
				qdf_mem_unmap_page(soc->osdev, paddr,
						   rx_desc_pool->buf_size,
						   QDF_DMA_FROM_DEVICE);
				rx_desc_pool->array[i].rx_desc.unmapped = 1;
			}
			qdf_frag_free(vaddr);
		}
	}
	qdf_spin_unlock_bh(&rx_desc_pool->lock);
}

qdf_export_symbol(dp_rx_desc_frag_free);
#endif

void dp_rx_desc_pool_free(struct dp_soc *soc,
			  struct rx_desc_pool *rx_desc_pool)
{
	qdf_mem_common_free(rx_desc_pool->array);
}

qdf_export_symbol(dp_rx_desc_pool_free);

void dp_rx_desc_pool_deinit(struct dp_soc *soc,
			    struct rx_desc_pool *rx_desc_pool,
			    uint32_t pool_id)
{
	if (rx_desc_pool->pool_size) {
		qdf_spin_lock_bh(&rx_desc_pool->lock);

		rx_desc_pool->freelist = NULL;
		rx_desc_pool->pool_size = 0;

		/* Deinitialize rx mon dest frag flag */
		rx_desc_pool->rx_mon_dest_frag_enable = false;

		soc->arch_ops.dp_rx_desc_pool_deinit(soc, rx_desc_pool,
						     pool_id);

		qdf_spin_unlock_bh(&rx_desc_pool->lock);
		qdf_spinlock_destroy(&rx_desc_pool->lock);
	}
}

qdf_export_symbol(dp_rx_desc_pool_deinit);

#endif /* RX_DESC_MULTI_PAGE_ALLOC */

void dp_rx_desc_pool_deinit_generic(struct dp_soc *soc,
			       struct rx_desc_pool *rx_desc_pool,
			       uint32_t pool_id)
{
}

uint16_t dp_rx_get_free_desc_list(struct dp_soc *soc, uint32_t pool_id,
				struct rx_desc_pool *rx_desc_pool,
				uint16_t num_descs,
				union dp_rx_desc_list_elem_t **desc_list,
				union dp_rx_desc_list_elem_t **tail)
{
	uint16_t count;

	qdf_spin_lock_bh(&rx_desc_pool->lock);

	*desc_list = *tail = rx_desc_pool->freelist;

	for (count = 0; count < num_descs; count++) {

		if (qdf_unlikely(!rx_desc_pool->freelist)) {
			qdf_spin_unlock_bh(&rx_desc_pool->lock);
			return count;
		}
		*tail = rx_desc_pool->freelist;
		rx_desc_pool->freelist = rx_desc_pool->freelist->next;
	}
	(*tail)->next = NULL;
	qdf_spin_unlock_bh(&rx_desc_pool->lock);
	return count;
}

qdf_export_symbol(dp_rx_get_free_desc_list);

void dp_rx_add_desc_list_to_free_list(struct dp_soc *soc,
				union dp_rx_desc_list_elem_t **local_desc_list,
				union dp_rx_desc_list_elem_t **tail,
				uint16_t pool_id,
				struct rx_desc_pool *rx_desc_pool)
{
	union dp_rx_desc_list_elem_t *temp_list = NULL;

	qdf_spin_lock_bh(&rx_desc_pool->lock);


	temp_list = rx_desc_pool->freelist;
	QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_DEBUG,
	"temp_list: %pK, *local_desc_list: %pK, *tail: %pK (*tail)->next: %pK",
	temp_list, *local_desc_list, *tail, (*tail)->next);
	rx_desc_pool->freelist = *local_desc_list;
	(*tail)->next = temp_list;
	*tail = NULL;
	*local_desc_list = NULL;

	qdf_spin_unlock_bh(&rx_desc_pool->lock);
}

qdf_export_symbol(dp_rx_add_desc_list_to_free_list);

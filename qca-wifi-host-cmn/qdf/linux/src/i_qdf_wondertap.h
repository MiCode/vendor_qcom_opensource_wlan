/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

/**
 * DOC: i_qdf_wondertap.h
 *
 * This file maps QDF wondertap types and functions to the underlying
 * wondertap driver interface, providing OS abstraction for wondertap
 * operations.
 */

#ifndef _I_QDF_WONDERTAP_H
#define _I_QDF_WONDERTAP_H

#include <wonder/wondertap.h>

#define QDF_WONDERTAP_HT_MAX_NSS WONDERTAP_HT_NSS_MAX
#define QDF_WONDERTAP_VHT_MAX_NSS WONDERTAP_VHT_NSS_MAX
#define QDF_WONDERTAP_HE_MAX_NSS WONDERTAP_HE_NSS_MAX
#define QDF_WONDERTAP_EHT_MAX_NSS WONDERTAP_EHT_NSS_MAX
#define QDF_WONDERTAP_FILTER_TYPE_FRAME WONDERTAP_FILTER_TYPE_FRAME

/**
 * typedef __qdf_wondertap_rate_bw_t - wondertap rate bandwidth type
 *
 * Wondertap rate bandwidth enumeration and maps to the underlying
 * wondertap_rate_bw enum.
 */
typedef enum wondertap_rate_bw __qdf_wondertap_rate_bw_t;

/**
 * typedef __qdf_wondertap_set_freq_params_t - wondertap frequency params
 *
 * Wondertap frequency configuration parameters and maps to the underlying
 * wondertap_set_freq_params structure.
 */
typedef struct wondertap_set_freq_params __qdf_wondertap_set_freq_params_t;

/**
 * typedef __qdf_wondertap_filter_type_t - wondertap filter type
 *
 * Wondertap filter type enumeration and maps to the underlying
 * wondertap_filter_type enum.
 */
typedef enum wondertap_filter_type __qdf_wondertap_filter_type_t;

/**
 * typedef __qdf_wondertap_frame_filter_params_t - wondertapframe filter
 *
 * Wondertap frame filter parameters and maps to the underlying
 * wondertap_frame_filter_params structure.
 */
typedef struct wondertap_frame_filter_params __qdf_wondertap_frame_filter_params_t;

/**
 * typedef __qdf_wondertap_rate_preamble_t - wondertap rate preamble type
 *
 * Wondertap rate preamble enumeration and maps to the underlying
 * wondertap_rate_preamble enum.
 */
typedef enum wondertap_rate_preamble __qdf_wondertap_rate_preamble_t;

/**
 * typedef __qdf_wondertap_rate_gi_t - wondertap guard interval type
 *
 * Wondertap guard interval enumeration and maps to the underlying
 * wondertap_rate_gi enum.
 */
typedef enum wondertap_rate_gi __qdf_wondertap_rate_gi_t;

/**
 * typedef __qdf_wondertap_tx_rate_params_t - wondertap TX rate parameters
 *
 * Wondertap TX rate configuration parameters and maps to the underlying
 * wondertap_fixed_tx_rate_params structure.
 */
typedef struct wondertap_fixed_tx_rate_params __qdf_wondertap_tx_rate_params_t;

/**
 * typedef __qdf_wondertap_tx_rate_mask_enable_t - wondertap rate mask enable
 *
 * Wondertap TX rate mask enable flags and maps to the underlying
 * wondertap_tx_rate_mask_enable enum.
 */
typedef enum wondertap_tx_rate_mask_enable __qdf_wondertap_tx_rate_mask_enable_t;

/**
 * typedef __qdf_wondertap_tx_rate_mask_params_t - wondertap rate mask params
 *
 * Wondertap TX rate mask parameters and maps to the underlying
 * wondertap_tx_rate_mask_params structure.
 */
typedef struct wondertap_tx_rate_mask_params __qdf_wondertap_tx_rate_mask_params_t;

/**
 * typedef __qdf_wondertap_capability_t - wondertap feature flags
 *
 * Wondertap feature capability flags and maps to the underlying
 * wondertap_features structure.
 */
typedef struct wondertap_capability __qdf_wondertap_capability_t;

/**
 * typedef __qdf_wonder_txd_t - wondertap TX descriptor
 *
 * Wondertap TX descriptor and maps to the underlying
 * wonder_txd structure.
 */
typedef struct wonder_txd __qdf_wonder_txd_t;

/**
 * typedef __qdf_wondertap_init_params_t - wondertap init parameters
 *
 * Wondertap initialization parameters and maps to the underlying
 * wondertap_init_params structure.
 */
typedef struct wondertap_init_params __qdf_wondertap_init_params_t;

/**
 * typedef __qdf_wondertap_deinit_params_t - wondertap deinit parameters
 *
 * Wondertap deinitialization parameters and maps to the underlying
 * wondertap_deinit_params structure.
 */
typedef struct wondertap_deinit_params __qdf_wondertap_deinit_params_t;

/**
 * typedef __qdf_wondertap_ops_t - wondertap operations structure
 *
 * Wondertap operations callbacks and maps to the underlying
 * wondertap_ops structure.
 */
typedef struct wondertap_ops __qdf_wondertap_ops_t;

/**
 * typedef __qdf_wondertap_priv_t - Wondertap private data structure
 *
 * Wondertap private data structure that holds version info and
 * operations table for vendor specific implementation.
 */
typedef struct wondertap_priv __qdf_wondertap_priv_t;
#endif /* _I_QDF_WONDERTAP_H */

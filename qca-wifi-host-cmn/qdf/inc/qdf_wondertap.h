/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

/**
 * DOC: qdf_wondertap.h
 *
 * QDF Wondertap Abstraction Layer
 *
 * This file provides the QDF abstraction layer for wondertap interface,
 * which enables passthrough mode operations for WLAN.
 */

#ifndef _QDF_WONDERTAP_H
#define _QDF_WONDERTAP_H

#include <i_qdf_wondertap.h>

/**
 * typedef qdf_wondertap_rate_bw_t - Wondertap rate bandwidth
 *
 * Defines the channel bandwidth for wondertap operations.
 * Supports 20MHz, 40MHz, 80MHz, and 160MHz bandwidths.
 */
typedef __qdf_wondertap_rate_bw_t qdf_wondertap_rate_bw_t;

/**
 * typedef qdf_wondertap_set_freq_params_t - Frequency configuration parameters
 *
 * Structure containing frequency and bandwidth settings for wondertap
 * channel configuration. Used to set the operating frequency and
 * channel bandwidth for passthrough mode operations.
 */
typedef __qdf_wondertap_set_freq_params_t qdf_wondertap_set_freq_params_t;

/**
 * typedef qdf_wondertap_filter_type_t - Wondertap filter type
 *
 * Defines the type of filtering to be applied in wondertap mode.
 * Currently supports frame-based filtering.
 */
typedef __qdf_wondertap_filter_type_t qdf_wondertap_filter_type_t;

/**
 * typedef qdf_wondertap_frame_filter_params_t - Frame filter parameters
 *
 * Structure containing frame filtering configuration including frame type,
 * subtype, and enable/disable state. Used to selectively filter frames
 * in passthrough mode based on 802.11 frame type and subtype.
 */
typedef __qdf_wondertap_frame_filter_params_t qdf_wondertap_frame_filter_params_t;

/**
 * typedef qdf_wondertap_rate_preamble_t - Rate preamble type
 *
 * Defines the preamble type for transmission rate configuration.
 * Supports Legacy, HT, VHT, HE, and EHT preambles for different
 * 802.11 standards.
 */
typedef __qdf_wondertap_rate_preamble_t qdf_wondertap_rate_preamble_t;

/**
 * typedef qdf_wondertap_rate_gi_t - Guard interval configuration
 *
 * Defines the guard interval (GI) for transmission rate configuration.
 * Supports default, short GI, and specific GI values (0.8us, 1.6us, 3.2us)
 * for different 802.11 standards.
 */
typedef __qdf_wondertap_rate_gi_t qdf_wondertap_rate_gi_t;

/**
 * typedef qdf_wondertap_tx_rate_params_t - TX rate parameters
 *
 * Structure containing complete TX rate configuration including preamble,
 * bandwidth, guard interval, NSS (Number of Spatial Streams), and MCS
 * (Modulation and Coding Scheme). Used to configure fixed transmission
 * rates in wondertap mode.
 */
typedef __qdf_wondertap_tx_rate_params_t qdf_wondertap_tx_rate_params_t;

/**
 * typedef qdf_wondertap_tx_rate_mask_enable_t - TX rate mask enable flags
 *
 * Bitmask flags to enable/disable specific rate types (Legacy, HT, VHT,
 * HE, EHT) in the TX rate mask configuration. Used for rate adaptation
 * control.
 */
typedef __qdf_wondertap_tx_rate_mask_enable_t qdf_wondertap_tx_rate_mask_enable_t;

/**
 * typedef qdf_wondertap_tx_rate_mask_params_t - TX rate mask parameters
 *
 * Structure containing rate mask configuration for all supported rate types.
 * Includes enable mask and per-NSS MCS masks for Legacy, HT, VHT, HE, and
 * EHT rates. Used to restrict available rates for rate adaptation algorithms.
 */
typedef __qdf_wondertap_tx_rate_mask_params_t qdf_wondertap_tx_rate_mask_params_t;

/**
 * typedef qdf_wondertap_capability_t - Wondertap capability flags
 *
 * Structure containing feature capability flags for wondertap interface.
 * Indicates support for rate adaptation, and coexistence with various
 * WLAN modes (STA, SAP, P2P, NAN, ranging).
 */
typedef __qdf_wondertap_capability_t qdf_wondertap_capability_t;

/**
 * typedef qdf_wonder_txd_t - Wondertap TX descriptor
 *
 * Structure containing TX descriptor information for wondertap packets.
 * Includes unicast/multicast indication, frame type, and TID (Traffic
 * Identifier) for QoS handling.
 */
typedef __qdf_wonder_txd_t qdf_wonder_txd_t;

/**
 * typedef qdf_wondertap_init_params_t - Wondertap initialization parameters
 *
 * Structure containing all parameters required for wondertap interface
 * initialization including channel configuration, TX rate settings,
 * MAC addresses, and retry limits.
 */
typedef __qdf_wondertap_init_params_t qdf_wondertap_init_params_t;

/**
 * typedef qdf_wondertap_deinit_params_t - Wondertap deinit parameters
 *
 * Structure containing country code for wondertap interface
 * deinitialization.
 */
typedef __qdf_wondertap_deinit_params_t qdf_wondertap_deinit_params_t;

/**
 * typedef qdf_wondertap_ops_t - Wondertap operations structure
 *
 * Structure containing function pointers for all wondertap operations
 * including initialization, deinitialization, frequency configuration,
 * filtering, rate control, regulatory settings, and feature queries.
 */
typedef __qdf_wondertap_ops_t qdf_wondertap_ops_t;

/**
 * typedef qdf_wondertap_priv_t - Wondertap private data structure
 *
 * Wondertap private data structure that holds version info and
 * operations table for vendor specific implementation.
 */
typedef __qdf_wondertap_priv_t qdf_wondertap_priv_t;
#endif /* _QDF_WONDERTAP_H */

/*
 * capnproto.c
 *
 * Copyright (C) 2023 by ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CAPNPROTO

#include "ndpi_api.h"

static void ndpi_int_capnproto_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                              struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found CapnProto\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CAPNPROTO, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_capnproto(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search CapnProto\n");

fprintf(stderr, "!!!!!!!!!!!!!!!!\n");
  if (packet->payload_packet_len < 4) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  const uint32_t segments = le32toh(get_u_int32_t(packet->payload, 0));
  const uint32_t segment_table_size = 4 * (segments + segments % 2);

  if (packet->payload_packet_len < segment_table_size) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  for (uint32_t i = 0; i <= segments; ++i)
  {
    fprintf(stderr, "___%u/%u___\n", i, segments);
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_capnproto_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                              u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("CapnProto", ndpi_struct, *id,
                                      NDPI_PROTOCOL_CAPNPROTO,
                                      ndpi_search_capnproto,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

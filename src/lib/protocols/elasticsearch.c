/*
 * elasticsearch.c
 *
 * Copyright (C) 2022 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ELASTICSEARCH

#include "ndpi_api.h"

static void ndpi_int_elasticsearch_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                  struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found elasticsearch\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_ELASTICSEARCH,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_elasticsearch(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  u_int32_t message_length;

  NDPI_LOG_DBG(ndpi_struct, "search elasticsearch\n");

  if (packet->payload_packet_len < 6)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (ntohs(get_u_int16_t(packet->payload, 0)) != 0x4553 /* "ES" */)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  message_length = ntohl(get_u_int32_t(packet->payload, 2));
  if (packet->payload_packet_len < message_length + 6)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_elasticsearch_add_connection(ndpi_struct, flow);
}

/* ***************************************************** */
  
void init_elasticsearch_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                  u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Elasticsearch", ndpi_struct, *id,
                                      NDPI_PROTOCOL_ELASTICSEARCH,
                                      ndpi_search_elasticsearch,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}

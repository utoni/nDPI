/*
 * telnet.c
 *
 * Copyright (C) 2011-26 - ntop.org
 * Copyright (C) 2009-11 - ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TELNET

#include "ndpi_api.h"
#include "ndpi_private.h"

/* #define TELNET_DEBUG 1 */

/* ************************************************************************ */

/*
 * Core byte-stream analysis logic shared by the direct path and the
 * TCP-reassembly callback.  Works on an arbitrary byte buffer rather
 * than on packet->payload so that the same code is called whether the
 * data arrived in-order or was reassembled from out-of-order segments.
 */
static void telnet_process_bytes(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow,
                                 u_int8_t direction,
                                 const u_int8_t *data, u_int16_t len)
{
  int i;

  /* Skip Telnet IAC command sequences and empty chunks */
  if(!data || len == 0 || data[0] == 0xFF)
    return;

  if(flow->protos.telnet.username_detected) {
    if((!flow->protos.telnet.password_found) && (len > 9)) {
      if(strncasecmp((char*)data, "password:", 9) == 0)
        flow->protos.telnet.password_found = 1;
      return;
    }

    if(data[0] == '\r' || data[0] == '\n') {
      if(!flow->protos.telnet.password_found)
        return;

      flow->protos.telnet.password_detected = 1;
      ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
      flow->protos.telnet.password[flow->protos.telnet.character_id] = '\0';
      return;
    }

    if(direction == 0) { /* client -> server */
      for(i = 0; i < len; i++) {
        if(flow->protos.telnet.character_id < (sizeof(flow->protos.telnet.password) - 1))
          flow->protos.telnet.password[flow->protos.telnet.character_id++] = data[i];
      }
    }
    return;
  }

  if((!flow->protos.telnet.username_found) && (len > 6)) {
    if(strncasecmp((char*)data, "login:", 6) == 0)
      flow->protos.telnet.username_found = 1;
    return;
  }

  if(data[0] == '\r' || data[0] == '\n') {
    char buf[64];

    flow->protos.telnet.username_detected = 1;
    flow->protos.telnet.username[flow->protos.telnet.character_id] = '\0';
    flow->protos.telnet.character_id = 0;

    snprintf(buf, sizeof(buf), "Found Telnet username (%s)",
             flow->protos.telnet.username);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);
    return;
  }

  for(i = 0; i < len; i++) {
    if(direction == 0) { /* client -> server */
      if(flow->protos.telnet.character_id < (sizeof(flow->protos.telnet.username) - 1)) {
        if(i >= len - 2 && (data[i] == '\r' || data[i] == '\n'))
          continue;
        else if(ndpi_isprint(data[i]) == 0)
          flow->protos.telnet.username[flow->protos.telnet.character_id++] = '?';
        else
          flow->protos.telnet.username[flow->protos.telnet.character_id++] = data[i];
      }
    }
  }
}

/* ************************************************************************ */

/*
 * TCP reassembly delivery callback for the Telnet dissector.
 *
 * Called by the reassembly engine whenever in-order stream bytes are
 * available (either because the segment arrived in-order, or because a
 * gap was filled and buffered out-of-order segments can now be drained).
 *
 * The ndpi_detection_module_struct pointer is passed via the per-call
 * context slot (ndpi_tcp_reassembly_set_ctx / ndpi_tcp_reassembly_get_ctx)
 * rather than through userdata so that userdata can hold the flow pointer
 * and both pointers remain available in the callback at the same time.
 */
static void telnet_reasm_cb(struct ndpi_tcp_reassembly *r,
                            u_int8_t direction,
                            u_int32_t seq,
                            const u_int8_t *data, u_int16_t len,
                            void *userdata)
{
  struct ndpi_flow_struct *flow =
    (struct ndpi_flow_struct *)userdata;
  struct ndpi_detection_module_struct *ndpi_struct =
    (struct ndpi_detection_module_struct *)ndpi_tcp_reassembly_get_ctx(r);

  (void)seq; /* sequence number not needed for content analysis */

  if(ndpi_struct && flow)
    telnet_process_bytes(ndpi_struct, flow, direction, data, len);
}

/* ************************************************************************ */

static int search_telnet_again(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

#ifdef TELNET_DEBUG
  printf("==> %s() [%.*s][direction: %u]\n", __FUNCTION__, packet->payload_packet_len,
         packet->payload, packet->packet_direction);
#endif

  if((packet->payload == NULL) || (packet->payload_packet_len == 0))
    return 1;

  if(flow->l4.tcp.tcp_reassembly && packet->tcp) {
    /*
     * Reassembly path: feed the raw TCP segment into the engine.
     * The engine will invoke telnet_reasm_cb() with the reassembled
     * in-order bytes, possibly combining this segment with previously
     * buffered out-of-order data.
     *
     * Set the per-call context to ndpi_struct so the callback can call
     * ndpi_set_risk() and other API functions that require it.
     */
    ndpi_tcp_reassembly_set_ctx(flow->l4.tcp.tcp_reassembly, ndpi_struct);
    ndpi_tcp_reassembly_process(flow->l4.tcp.tcp_reassembly,
                                packet->packet_direction,
                                ntohl(packet->tcp->seq),
                                0 /* not SYN */,
                                packet->payload,
                                packet->payload_packet_len);
  } else {
    /* Direct path (no reassembly): process the packet payload as-is. */
    telnet_process_bytes(ndpi_struct, flow, packet->packet_direction,
                         packet->payload, packet->payload_packet_len);
  }

  /* Return 0 to stop extra-packet processing once the password was found. */
  return flow->protos.telnet.password_detected ? 0 : 1;
}

/* ************************************************************************ */

static void ndpi_int_telnet_add_connection(struct ndpi_detection_module_struct
                                           *ndpi_struct, struct ndpi_flow_struct *flow) {
  flow->max_extra_packets_to_check = 64;
  flow->extra_packets_func = search_telnet_again;

  /*
   * Allocate the per-flow TCP reassembly engine.  userdata = flow so the
   * delivery callback can update flow->protos.telnet.  The ndpi_struct
   * pointer is supplied per-call via the ctx slot.
   *
   * If allocation fails we fall back silently to the direct-payload path.
   */
  if(!flow->l4.tcp.tcp_reassembly)
    flow->l4.tcp.tcp_reassembly =
      ndpi_tcp_reassembly_alloc(0, telnet_reasm_cb, flow);

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TELNET, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* ************************************************************************ */

#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int8_t search_iac(struct ndpi_detection_module_struct *ndpi_struct) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  u_int16_t a;

#ifdef TELNET_DEBUG
  printf("==> %s()\n", __FUNCTION__);
#endif

  if(packet->payload_packet_len < 3)
    return(0);

  if(!((packet->payload[0] == 0xff)
       && (packet->payload[1] > 0xf9)
       && (packet->payload[1] != 0xff)
       && (packet->payload[2] < 0x28)))
    return(0);

  a = 3;

  while (a < packet->payload_packet_len - 2) {
    // commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
    // command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
    if(!(packet->payload[a] != 0xff ||
          (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xf0) && (packet->payload[a + 1] <= 0xfa)) ||
          (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xfb) && (packet->payload[a + 1] != 0xff)
           && (packet->payload[a + 2] <= 0x28))))
      return(0);

    a += 3;
  }

  return 1;
}

/* ************************************************************************ */

/* this detection also works asymmetrically */
static void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search telnet\n");

  if(search_iac(ndpi_struct) == 1) {
    NDPI_LOG_INFO(ndpi_struct, "found telnet\n");
    ndpi_int_telnet_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);

  return;
}


void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Telnet", ndpi_struct,
                     ndpi_search_telnet_tcp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_TELNET);
  /*
   * Declare that this dissector uses the TCP reassembly engine.
   * The framework will automatically free flow->l4.tcp.tcp_reassembly
   * in ndpi_free_flow_data() when the flow is torn down.
   */
  ndpi_enable_tcp_reassembly(ndpi_struct, NDPI_PROTOCOL_TELNET);
}

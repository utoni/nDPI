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

static int search_telnet_again(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *data = packet->payload;
  u_int16_t data_len   = packet->payload_packet_len;
  int i;

  /* If TCP reassembly is active, use the accumulated in-order buffer */
  if(flow->l4.tcp.tcp_reassembly) {
    u_int32_t rlen = 0;
    const u_int8_t *rbuf = ndpi_tcp_reassembly_get_buffer(
        flow->l4.tcp.tcp_reassembly, packet->packet_direction, &rlen);
    if(rbuf && rlen > 0) {
      data     = rbuf;
      data_len = (rlen > 0xFFFF) ? 0xFFFF : (u_int16_t)rlen;
    }
  }

#ifdef TELNET_DEBUG
  printf("==> %s() [%.*s][direction: %u]\n", __FUNCTION__, data_len,
	 data, packet->packet_direction);
#endif
  
  if((data == NULL)
     || (data_len == 0)
     || (data[0] == 0xFF))
    return(1);

  if(flow->protos.telnet.username_detected) {
    if((!flow->protos.telnet.password_found)
	&& (data_len > 9)) {
	
      if(strncasecmp((char*)data, "password:", 9) == 0) {
	flow->protos.telnet.password_found = 1;
      }

      return(1);
    }
      
    if(data[0] == '\r' || data[0] == '\n') {
      if(!flow->protos.telnet.password_found)
	return(1);
	
      flow->protos.telnet.password_detected = 1;
      ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
      flow->protos.telnet.password[flow->protos.telnet.character_id] = '\0';
      return(0);
    }

    if(packet->packet_direction == 0) /* client -> server */ {
      for(i=0; i<data_len; i++) {
	if(flow->protos.telnet.character_id < (sizeof(flow->protos.telnet.password)-1))
	  flow->protos.telnet.password[flow->protos.telnet.character_id++] = data[i];
      }
    }

    return(1);
  }

  if((!flow->protos.telnet.username_found)
     && (data_len > 6)) {

    if(strncasecmp((char*)data, "login:", 6) == 0) {
      flow->protos.telnet.username_found = 1;
    }

    return(1);
  }

  if(data[0] == '\r' || data[0] == '\n') {
    char buf[64];
    
    flow->protos.telnet.username_detected = 1;
    flow->protos.telnet.username[flow->protos.telnet.character_id] = '\0';
    flow->protos.telnet.character_id = 0;

    snprintf(buf, sizeof(buf), "Found Telnet username (%s)",
	     flow->protos.telnet.username);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);

    return(1);
  }

  for(i=0; i<data_len; i++) {
    if(packet->packet_direction == 0) /* client -> server */ {
      if(flow->protos.telnet.character_id < (sizeof(flow->protos.telnet.username)-1))
      {
        if (i>=data_len-2 &&
            (data[i] == '\r' || data[i] == '\n'))
        {
          continue;
        }
        else if (ndpi_isprint(data[i]) == 0)
        {
          flow->protos.telnet.username[flow->protos.telnet.character_id++] = '?';
        } else {
          flow->protos.telnet.username[flow->protos.telnet.character_id++] = data[i];
        }
      }
    }
  }

  /* Possibly more processing */
  return(1);
}

/* ************************************************************************ */

static void ndpi_int_telnet_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow) {
  flow->max_extra_packets_to_check = 64;
  flow->extra_packets_func = search_telnet_again;

  /* Allocate per-flow TCP reassembly handle (accumulation mode: NULL callback).
   * The framework feeds each segment before calling search_telnet_again and
   * frees the accumulated buffer afterwards (default discard behaviour). */
  if(!flow->l4.tcp.tcp_reassembly)
    flow->l4.tcp.tcp_reassembly = ndpi_tcp_reassembly_alloc(0, NULL, NULL);

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
  /* Register this dissector as a TCP-reassembly user so that the framework:
   *  - feeds each TCP segment to the engine before calling search_telnet_again
   *  - frees the accumulated buffer after each call (default discard)
   *  - frees flow->l4.tcp.tcp_reassembly in ndpi_free_flow_data() */
  ndpi_enable_tcp_reassembly(ndpi_struct, NDPI_PROTOCOL_TELNET);
}

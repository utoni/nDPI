/*
 * unit.c
 *
 * Copyright (C) 2019-20 - ntop.org
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

#ifdef __linux__
#include <sched.h>
#endif /* linux */

#ifdef WIN32
#include <winsock2.h>
#include <process.h>
#include <io.h>
#else
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_define.h"

#include "json.h" /* JSON-C */

static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
static int verbose = 0;

/* *********************************************** */

#define FLT_MAX 3.402823466e+38F

int serializerUnitTest() {
  ndpi_serializer serializer, serializer_cloned, deserializer;
  int i, loop_id;
  ndpi_serialization_format fmt = {0};
  u_int32_t buffer_len;
  char *buffer;
  enum json_tokener_error jerr;
  json_object *j;

  memset(&serializer, 0, sizeof(serializer));
  memset(&serializer_cloned, 0, sizeof(serializer_cloned));
  memset(&deserializer, 0, sizeof(deserializer));
  
  for(loop_id=0; loop_id<3; loop_id++) {
    switch(loop_id) {
    case 0:
      if (verbose) printf("--- TLV test ---\n");
      fmt = ndpi_serialization_format_tlv;
      break;

    case 1:
      if (verbose) printf("--- JSON test ---\n");
      fmt = ndpi_serialization_format_json;
      break;

    case 2:
      if (verbose) printf("--- CSV test ---\n");
      fmt = ndpi_serialization_format_csv;
      break;
    }
    assert(ndpi_init_serializer(&serializer, fmt) != -1);

    for(i=0; i<16; i++) {
      char kbuf[32], vbuf[32];
      int j = 0;
      ndpi_snprintf(vbuf, sizeof(vbuf), "Value %d \t with special chars:\n$!@?", i);
      assert(ndpi_serialize_uint32_uint32(&serializer, j++, i*i) != -1);
      assert(ndpi_serialize_uint32_string(&serializer, j++, "Data") != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_uint32(&serializer, kbuf, i*i) != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      if (fmt != ndpi_serialization_format_tlv) {
        ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
        assert(ndpi_serialize_string_double(&serializer, kbuf, ((double)(FLT_MAX))*2, "%lf") != -1);
      }
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_int64(&serializer,  kbuf, INT64_MAX) != -1);
      assert(ndpi_serialize_string_string(&serializer, "utf-8", "küche") != -1);
      if ((i&0x3) == 0x3) ndpi_serialize_end_of_record(&serializer);
    }

    if (fmt == ndpi_serialization_format_json) {
      assert(ndpi_serialize_start_of_list(&serializer, "List") != -1);

      for(i=0; i<4; i++) {
	char kbuf[32], vbuf[32];
	ndpi_snprintf(kbuf, sizeof(kbuf), "Ignored");
	ndpi_snprintf(vbuf, sizeof(vbuf), "Item %d", i);
	assert(ndpi_serialize_uint32_uint32(&serializer, i, i*i) != -1);
	assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
	assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      }
      assert(ndpi_serialize_end_of_list(&serializer) != -1);
      assert(ndpi_serialize_string_string(&serializer, "Last", "Ok") != -1);

      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

      if(verbose)
	printf("%s\n", buffer);

      /* Decoding JSON to validate syntax */
      jerr = json_tokener_success;
      j = json_tokener_parse_verbose(buffer, &jerr);
      if (j == NULL) {
        printf("%s: ERROR (json validation failed: `%s')\n",
               __func__, json_tokener_error_desc(jerr));
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }

    } else if (fmt == ndpi_serialization_format_csv) {
      if(verbose) {

	buffer_len = 0;
	buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
	printf("%s\n", buffer);

	buffer_len = 0;
	buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
	printf("%s\n", buffer);
      }

    } else {
      if(verbose)
	printf("Serialization size: %u\n", ndpi_serializer_get_buffer_len(&serializer));

      assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);

      while(1) {
	ndpi_serialization_type kt, et;

	et = ndpi_deserialize_get_item_type(&deserializer, &kt);

	if(et == ndpi_serialization_unknown) {
	  break;
        } else if(et == ndpi_serialization_end_of_record) {
          if (verbose) printf("EOR\n");
	} else {
	  u_int32_t k32, v32;
          int64_t v64;
	  ndpi_string ks, vs;
	  float vf;
	  double vd;

	  switch(kt) {
          case ndpi_serialization_uint32:
            ndpi_deserialize_key_uint32(&deserializer, &k32);
	    if(verbose) printf("%u=", k32);
	    break;
          case ndpi_serialization_string:
            ndpi_deserialize_key_string(&deserializer, &ks);
            if (verbose) {
              u_int8_t bkp = ks.str[ks.str_len];
	      ks.str[ks.str_len] = '\0';
              printf("%s=", ks.str);
	      ks.str[ks.str_len] = bkp;
            }
	    break;
          default:
            printf("%s: ERROR Unsupported TLV key type %u (value type %u)\n", __func__, kt, et);
	    return -1;
	  }

	  switch(et) {
          case ndpi_serialization_uint32:
	    assert(ndpi_deserialize_value_uint32(&deserializer, &v32) != -1);
	    if(verbose) printf("%u\n", v32);
	    break;

          case ndpi_serialization_int64:
	    assert(ndpi_deserialize_value_int64(&deserializer, &v64) != -1);
	    if(verbose) printf("%" PRId64 "\n", v64);
	    break;

          case ndpi_serialization_string:
	    assert(ndpi_deserialize_value_string(&deserializer, &vs) != -1);
	    if(verbose) {
	      u_int8_t bkp = vs.str[vs.str_len];
	      vs.str[vs.str_len] = '\0';
	      printf("%s\n", vs.str);
	      vs.str[vs.str_len] = bkp;
	    }
	    break;

          case ndpi_serialization_float:
	    assert(ndpi_deserialize_value_float(&deserializer, &vf) != -1);
	    if(verbose) printf("%f\n", vf);
	    break;

          case ndpi_serialization_double:
	    assert(ndpi_deserialize_value_double(&deserializer, &vd) != -1);
	    if(verbose) printf("%lf\n", vd);
	    break;

          default:
	    if (verbose) printf("\n");
            printf("%s: ERROR Unsupported TLV value type %u (key type %u)\n", __func__, et, kt);
	    return -1;
	  }
	}

	ndpi_deserialize_next(&deserializer);
      }

      /* Converting from TLV to JSON */

      assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);
      assert(ndpi_init_serializer(&serializer_cloned, ndpi_serialization_format_json) != -1);
      assert(ndpi_deserialize_clone_all(&deserializer, &serializer_cloned) == 0);

      buffer = ndpi_serializer_get_buffer(&serializer_cloned, &buffer_len);
      if(verbose)
        printf("TLV->JSON: %s\n", buffer);

      ndpi_term_serializer(&serializer_cloned);
    }

    ndpi_term_serializer(&serializer);
  }

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int serializeProtoUnitTest(void)
{
  ndpi_serializer serializer;
  int loop_id;
  ndpi_serialization_format fmt = {0};
  u_int32_t buffer_len;
  char * buffer;

  for(loop_id=0; loop_id<3; loop_id++) {
    switch(loop_id) {
    case 0:
      if (verbose) printf("--- TLV test ---\n");
      fmt = ndpi_serialization_format_tlv;
      break;

    case 1:
      if (verbose) printf("--- JSON test ---\n");
      fmt = ndpi_serialization_format_json;
      break;

    case 2:
      if (verbose) printf("--- CSV test ---\n");
      fmt = ndpi_serialization_format_csv;
      break;
    }
    assert(ndpi_init_serializer(&serializer, fmt) != -1);

    ndpi_protocol ndpi_proto;
    ndpi_risk risks = 0;

    ndpi_proto.proto.master_protocol = NDPI_PROTOCOL_TLS,
      ndpi_proto.proto.app_protocol = NDPI_PROTOCOL_FACEBOOK,
      ndpi_proto.protocol_by_ip = NDPI_PROTOCOL_FACEBOOK,
      ndpi_proto.category = NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
      ndpi_proto.breed = NDPI_PROTOCOL_FUN;
       
    NDPI_SET_BIT(risks, NDPI_MALFORMED_PACKET);
    NDPI_SET_BIT(risks, NDPI_TLS_WEAK_CIPHER);
    NDPI_SET_BIT(risks, NDPI_TLS_OBSOLETE_VERSION);
    NDPI_SET_BIT(risks, NDPI_TLS_SELFSIGNED_CERTIFICATE);
    ndpi_serialize_proto(ndpi_info_mod, &serializer, risks, NDPI_CONFIDENCE_DPI, ndpi_proto);
    assert(ndpi_serialize_string_float(&serializer,  "float", FLT_MAX, "%f") != -1);
    if (fmt != ndpi_serialization_format_tlv)
      assert(ndpi_serialize_string_double(&serializer,  "double", ((double)(FLT_MAX))*2, "%lf") != -1);

    if (fmt == ndpi_serialization_format_json)
    {
      buffer_len = 0;
      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
#ifndef WIN32
      char const * const expected_json_str = "{\"flow_risk\": {\"6\": {\"risk\":\"Self-signed Cert\",\"severity\":\"High\",\"risk_score\": {\"total\":300,\"client\":270,\"server\":30}},\"7\": {\"risk\":\"Obsolete TLS (v1.1 or older)\",\"severity\":\"High\",\"risk_score\": {\"total\":310,\"client\":275,\"server\":35}},\"8\": {\"risk\":\"Weak TLS Cipher\",\"severity\":\"High\",\"risk_score\": {\"total\":150,\"client\":135,\"server\":15}},\"17\": {\"risk\":\"Malformed Packet\",\"severity\":\"Low\",\"risk_score\": {\"total\":160,\"client\":80,\"server\":80}}},\"confidence\": {\"6\":\"DPI\"},\"proto\":\"TLS.Facebook\",\"proto_id\":\"91.119\",\"proto_by_ip\":\"Facebook\",\"proto_by_ip_id\":119,\"encrypted\":1,\"breed\":\"Fun\",\"category_id\":6,\"category\":\"SocialNetwork\",\"float\":340282346638528859811704183484516925440.000000,\"double\":680564693277057719623408366969033850880.000000}";

      if (strncmp(buffer, expected_json_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected JSON str: \"%s\"\n", __func__, expected_json_str);
        printf("%s: ERROR: got JSON str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
        return -1;
      }
#endif

      if(verbose)
        printf("%s\n", buffer);

      /* Decoding JSON to validate syntax */
      enum json_tokener_error jerr = json_tokener_success;
      json_object * const j = json_tokener_parse_verbose(buffer, &jerr);
      if (j == NULL) {
        printf("%s: ERROR (json validation failed: `%s')\n",
               __func__, json_tokener_error_desc(jerr));
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }
    } else if (fmt == ndpi_serialization_format_csv)
    {
      char const * const expected_csv_hdr_str = "risk,severity,total,client,server,risk,severity,total,client,server,risk,severity,total,client,server,risk,severity,total,client,server,6,proto,proto_id,proto_by_ip,proto_by_ip_id,encrypted,breed,category_id,category,float,double";
      buffer_len = 0;
      buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
      assert(buffer != NULL && buffer_len != 0);
      if (verbose)
        printf("%s\n", buffer);
      if (strncmp(buffer, expected_csv_hdr_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected CSV str: \"%s\"\n", __func__, expected_csv_hdr_str);
        printf("%s: ERROR: got CSV str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
      }

#ifndef WIN32
      char const * const expected_csv_buf_str = "Self-signed Cert,High,300,270,30,Obsolete TLS (v1.1 or older),High,310,275,35,Weak TLS Cipher,High,150,135,15,Malformed Packet,Low,160,80,80,DPI,TLS.Facebook,91.119,Facebook,119,1,Fun,6,SocialNetwork,340282346638528859811704183484516925440.000000,680564693277057719623408366969033850880.000000";
      buffer_len = 0;
      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
      assert(buffer != NULL && buffer_len != 0);
      if (verbose)
          printf("%s\n", buffer);
      if (strncmp(buffer, expected_csv_buf_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected CSV str: \"%s\"\n", __func__, expected_csv_buf_str);
        printf("%s: ERROR: got CSV str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
      }
    }
#endif

    ndpi_term_serializer(&serializer);
  }

  printf("%30s                      OK\n", __func__);

  return 0;
}

/* *********************************************** */

/*
 * Collected bytes from the reassembly callback for verification.
 */
#define REASM_TEST_BUF_SIZE 4096
static u_int8_t  reasm_collected[2][REASM_TEST_BUF_SIZE];
static u_int16_t reasm_collected_len[2];

static void reasm_test_cb(struct ndpi_tcp_reassembly *r,
                          u_int8_t direction,
                          u_int32_t seq,
                          const u_int8_t *data,
                          u_int16_t len,
                          void *userdata)
{
  (void)r; (void)seq; (void)userdata;
  if(direction > 1) return;
  if((u_int32_t)reasm_collected_len[direction] + len <= REASM_TEST_BUF_SIZE) {
    memcpy(&reasm_collected[direction][reasm_collected_len[direction]], data, len);
    reasm_collected_len[direction] += len;
  }
}

static void reasm_reset_collected(void)
{
  memset(reasm_collected, 0, sizeof(reasm_collected));
  reasm_collected_len[0] = reasm_collected_len[1] = 0;
}

int tcpReassemblyUnitTest(void)
{
  struct ndpi_tcp_reassembly *r;
  ndpi_tcp_reassembly_stats stats;

  /* ---------- 1. Allocation & free (smoke test) ---------- */
  r = ndpi_tcp_reassembly_alloc(0, NULL, NULL);
  assert(r != NULL);
  ndpi_tcp_reassembly_free(r);

  /* ---------- 2. In-order delivery ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  /* SYN: ISN = 100 */
  assert(ndpi_tcp_reassembly_process(r, 0, 100, 1, NULL, 0) == 0);

  /* Three in-order segments: "Hello", " ", "World" */
  assert(ndpi_tcp_reassembly_process(r, 0, 101, 0, (const u_int8_t *)"Hello", 5) == 0);
  assert(ndpi_tcp_reassembly_process(r, 0, 106, 0, (const u_int8_t *)" ", 1) == 0);
  assert(ndpi_tcp_reassembly_process(r, 0, 107, 0, (const u_int8_t *)"World", 5) == 0);

  assert(reasm_collected_len[0] == 11);
  assert(memcmp(reasm_collected[0], "Hello World", 11) == 0);

  ndpi_tcp_reassembly_get_stats(r, 0, &stats);
  assert(stats.next_seq == 112);
  assert(stats.ooo_buf_size == 0);
  assert(stats.ooo_seg_count == 0);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 3. Out-of-order delivery ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  /* SYN: ISN = 0, so first data byte has seq=1 */
  assert(ndpi_tcp_reassembly_process(r, 0, 0, 1, NULL, 0) == 0);

  /*
   * Stream is: "Hello"(seq=1,len=5) " "(seq=6,len=1) "World"(seq=7,len=5)
   * Send segments 2 and 3 out-of-order before segment 1.
   */
  assert(ndpi_tcp_reassembly_process(r, 0, 7, 0, (const u_int8_t *)"World", 5) == 0);
  assert(ndpi_tcp_reassembly_process(r, 0, 6, 0, (const u_int8_t *)" ", 1) == 0);

  /* Nothing delivered yet */
  assert(reasm_collected_len[0] == 0);

  ndpi_tcp_reassembly_get_stats(r, 0, &stats);
  assert(stats.ooo_buf_size == 6);
  assert(stats.ooo_seg_count == 2);

  /* Now segment 1 arrives – should trigger delivery of all three */
  assert(ndpi_tcp_reassembly_process(r, 0, 1, 0, (const u_int8_t *)"Hello", 5) == 0);

  assert(reasm_collected_len[0] == 11);
  assert(memcmp(reasm_collected[0], "Hello World", 11) == 0);

  ndpi_tcp_reassembly_get_stats(r, 0, &stats);
  assert(stats.ooo_buf_size == 0);
  assert(stats.ooo_seg_count == 0);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 4. Retransmission (pure duplicate) ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  assert(ndpi_tcp_reassembly_process(r, 0, 0, 1, NULL, 0) == 0);
  assert(ndpi_tcp_reassembly_process(r, 0, 1, 0, (const u_int8_t *)"ABCD", 4) == 0);
  /* Retransmission of exact same segment – must not duplicate data */
  assert(ndpi_tcp_reassembly_process(r, 0, 1, 0, (const u_int8_t *)"ABCD", 4) == 0);

  assert(reasm_collected_len[0] == 4);
  assert(memcmp(reasm_collected[0], "ABCD", 4) == 0);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 5. Retransmission with overlapping tail ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  assert(ndpi_tcp_reassembly_process(r, 0, 0, 1, NULL, 0) == 0);
  /* Segment 1: bytes 1-4 */
  assert(ndpi_tcp_reassembly_process(r, 0, 1, 0, (const u_int8_t *)"ABCD", 4) == 0);
  /* Segment overlapping: bytes 3-6, first two bytes already seen */
  assert(ndpi_tcp_reassembly_process(r, 0, 3, 0, (const u_int8_t *)"CDEF", 4) == 0);

  /* Should have "ABCDEF" */
  assert(reasm_collected_len[0] == 6);
  assert(memcmp(reasm_collected[0], "ABCDEF", 6) == 0);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 6. OOO budget exhaustion ---------- */
  r = ndpi_tcp_reassembly_alloc(10 /* only 10 bytes OOO budget */,
                                reasm_test_cb, NULL);
  assert(r != NULL);

  assert(ndpi_tcp_reassembly_process(r, 0, 0, 1, NULL, 0) == 0);
  /* Try to buffer 15 bytes out-of-order – should fail (-1) */
  assert(ndpi_tcp_reassembly_process(r, 0, 100, 0,
                                     (const u_int8_t *)"123456789012345", 15) == -1);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 7. Reset ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  assert(ndpi_tcp_reassembly_process(r, 0, 0, 1, NULL, 0) == 0);
  assert(ndpi_tcp_reassembly_process(r, 0, 1, 0, (const u_int8_t *)"AAA", 3) == 0);

  /* Simulate RST / new connection */
  ndpi_tcp_reassembly_reset(r, 0);

  ndpi_tcp_reassembly_get_stats(r, 0, &stats);
  assert(stats.next_seq == 0);
  assert(stats.ooo_buf_size == 0);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 8. Bidirectional streams are independent ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  /* Direction 0 (client -> server) */
  assert(ndpi_tcp_reassembly_process(r, 0, 0, 1, NULL, 0) == 0);
  assert(ndpi_tcp_reassembly_process(r, 0, 1, 0, (const u_int8_t *)"GET /", 5) == 0);

  /* Direction 1 (server -> client) */
  assert(ndpi_tcp_reassembly_process(r, 1, 0, 1, NULL, 0) == 0);
  assert(ndpi_tcp_reassembly_process(r, 1, 1, 0, (const u_int8_t *)"HTTP/1.1", 8) == 0);

  assert(reasm_collected_len[0] == 5);
  assert(memcmp(reasm_collected[0], "GET /", 5) == 0);
  assert(reasm_collected_len[1] == 8);
  assert(memcmp(reasm_collected[1], "HTTP/1.1", 8) == 0);

  ndpi_tcp_reassembly_free(r);

  /* ---------- 9. Sequence number wrap-around ---------- */
  reasm_reset_collected();
  r = ndpi_tcp_reassembly_alloc(0, reasm_test_cb, NULL);
  assert(r != NULL);

  /*
   * ISN chosen so that data crosses the 32-bit wrap boundary:
   *   SYN at 0xFFFFFFFC -> next_seq = 0xFFFFFFFD
   *   "WRAP" (4 bytes) at 0xFFFFFFFD -> wraps to 0x00000001
   *   "OK"   (2 bytes) at 0x00000001 -> ends at 0x00000003
   */
  assert(ndpi_tcp_reassembly_process(r, 0, 0xFFFFFFFCu, 1, NULL, 0) == 0);

  assert(ndpi_tcp_reassembly_process(r, 0, 0xFFFFFFFDu, 0,
                                     (const u_int8_t *)"WRAP", 4) == 0);

  assert(ndpi_tcp_reassembly_process(r, 0, 0x00000001u, 0,
                                     (const u_int8_t *)"OK", 2) == 0);

  assert(reasm_collected_len[0] == 6);
  assert(memcmp(reasm_collected[0], "WRAPOK", 6) == 0);

  ndpi_tcp_reassembly_free(r);

  printf("%30s                      OK\n", __func__);

  return 0;
}

/* *********************************************** */

int main(int argc, char **argv) {
#ifndef WIN32
  int c;
#endif
  (void)argc;
  (void)argv;
  
  if (ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return -1;
  }

  ndpi_info_mod = ndpi_init_detection_module(NULL);

  if (ndpi_info_mod == NULL)
    return -1;

  if(ndpi_finalize_initialization(ndpi_info_mod) != 0)
    return -1;

/*
 * If we want argument parsing on Windows,
 * we need to re-implement it as Windows has no such function.
 */
#ifndef WIN32
  while((c = getopt(argc, argv, "vh")) != -1) {
    switch(c) {
    case 'v':
      verbose = 1;
      break;
      
    default:
      printf("Usage: unit [-v] [-h]\n");
      return(0);
    }
  }
#else
  verbose = 0;
#endif
    
  /* Tests */
  if (serializerUnitTest() != 0) return -1;
  if (serializeProtoUnitTest() != 0) return -1;
  if (tcpReassemblyUnitTest() != 0) return -1;

  return 0;
}


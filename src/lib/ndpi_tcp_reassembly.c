/*
 * ndpi_tcp_reassembly.c
 *
 * TCP segment reassembly engine with out-of-order packet support.
 *
 * Copyright (C) 2011-26 - ntop.org and contributors
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
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"

/* ----------------------------------------------------------------
 * Internal data structures (not exposed in the public API)
 * ---------------------------------------------------------------- */

/*
 * A single out-of-order TCP segment stored in the OOO list.
 * The payload bytes immediately follow this header in the same
 * allocation, so we only call ndpi_malloc/ndpi_free once per
 * segment.
 */
struct ndpi_tcp_segment {
  u_int32_t seq;                  /* First sequence number of this segment   */
  u_int16_t len;                  /* Payload length                          */
  struct ndpi_tcp_segment *next;  /* Next segment (sorted by seq, ascending) */
  /* Payload bytes follow immediately after this struct in memory */
};

/* Access the inline payload of a segment */
#define SEGMENT_DATA(seg) ((u_int8_t *)((seg) + 1))

/*
 * Per-direction reassembly state.
 */
struct ndpi_tcp_stream {
  u_int32_t               next_seq;      /* Next expected sequence number  */
  struct ndpi_tcp_segment *ooo_list;     /* Sorted OOO segment list        */
  u_int32_t               ooo_buf_size;  /* Total bytes buffered in OOO    */
  u_int8_t                initialized;   /* 1 once first segment is seen   */
};

/*
 * Top-level reassembly object returned to the caller.
 */
struct ndpi_tcp_reassembly {
  struct ndpi_tcp_stream    streams[2];         /* [0]=cli->srv [1]=srv->cli */
  u_int32_t                 max_ooo_buf_size;   /* OOO budget per direction  */
  ndpi_tcp_reassembly_cb_t  callback;           /* Delivery callback         */
  void                     *userdata;
};

/* ----------------------------------------------------------------
 * Helper: 32-bit sequence number comparison with wrap-around.
 *
 *  seq_lt(a, b)  true if a is "before" b in TCP seq-space
 *  seq_leq(a, b) true if a <= b in TCP seq-space
 * ---------------------------------------------------------------- */
static inline int seq_lt(u_int32_t a, u_int32_t b)  { return (int32_t)(a - b) < 0; }
static inline int seq_leq(u_int32_t a, u_int32_t b) { return (int32_t)(a - b) <= 0; }

/* ----------------------------------------------------------------
 * Helper: deliver data to the user callback
 * ---------------------------------------------------------------- */
static void deliver(struct ndpi_tcp_reassembly *r,
                    u_int8_t direction,
                    u_int32_t seq,
                    const u_int8_t *data,
                    u_int16_t len)
{
  if(r->callback && len > 0)
    r->callback(r, direction, seq, data, len, r->userdata);
}

/* ----------------------------------------------------------------
 * Helper: free the entire OOO list for a stream
 * ---------------------------------------------------------------- */
static void free_ooo_list(struct ndpi_tcp_stream *st)
{
  struct ndpi_tcp_segment *seg = st->ooo_list;

  while(seg) {
    struct ndpi_tcp_segment *next = seg->next;
    ndpi_free(seg);
    seg = next;
  }

  st->ooo_list = NULL;
  st->ooo_buf_size = 0;
}

/* ----------------------------------------------------------------
 * Helper: insert a segment into the sorted OOO list.
 *
 * The list is sorted ascending by seq.  Overlapping / duplicate
 * segments are trimmed so that each byte appears at most once.
 *
 * Returns 0 on success, -1 if the OOO budget is exhausted.
 * ---------------------------------------------------------------- */
static int ooo_insert(struct ndpi_tcp_stream *st,
                      u_int32_t seq,
                      const u_int8_t *data,
                      u_int16_t len,
                      u_int32_t max_ooo_buf_size)
{
  u_int32_t seq_end;       /* exclusive end of the new segment */
  struct ndpi_tcp_segment **pp;
  struct ndpi_tcp_segment  *seg;
  u_int16_t actual_len;
  u_int32_t actual_seq;

  if(len == 0)
    return 0;

  seq_end = seq + len;

  /* ---- Walk the sorted list:
   *  1. Skip (and trim) any existing segments that cover bytes
   *     already present in the incoming segment.
   *  2. Find the insertion point.
   * ---- */

  /* First, trim the new segment's leading bytes if they overlap
   * with data we already have buffered earlier in the list.       */
  actual_seq = seq;
  actual_len = len;

  pp = &st->ooo_list;
  while(*pp && seq_lt((*pp)->seq, seq_end)) {
    struct ndpi_tcp_segment *cur = *pp;
    u_int32_t cur_end = cur->seq + cur->len;

    if(seq_leq(cur_end, actual_seq)) {
      /* cur is entirely before the new segment – skip */
      pp = &cur->next;
      continue;
    }

    if(seq_leq(seq_end, cur->seq)) {
      /* New segment is entirely before cur – stop scanning */
      break;
    }

    /* There is some overlap between cur and [actual_seq, seq_end).
     * Trim the new data to cover only the uncovered bytes.
     *
     * Case A: cur starts before the new segment
     *   cur:  [-----)
     *   new:      [-----)
     *   => trim new's leading bytes
     */
    if(seq_leq(cur->seq, actual_seq)) {
      if(seq_leq(seq_end, cur_end)) {
        /* New segment is entirely covered – nothing to insert */
        return 0;
      }
      /* Advance past cur's coverage */
      actual_seq = cur_end;
      actual_len = (u_int16_t)(seq_end - actual_seq);
      pp = &cur->next;
      continue;
    }

    /*
     * Case B: new segment starts before cur
     *   new:  [-----)
     *   cur:      [-----)
     *   => keep new's bytes up to cur->seq, then stop (we won't
     *      replace cur, we just stop before it).
     */
    actual_len = (u_int16_t)(cur->seq - actual_seq);
    break;
  }

  if(actual_len == 0)
    return 0;

  /* Check OOO budget */
  if(st->ooo_buf_size + actual_len > max_ooo_buf_size)
    return -1;

  /* Allocate segment + inline payload */
  seg = (struct ndpi_tcp_segment *)ndpi_malloc(
          sizeof(struct ndpi_tcp_segment) + actual_len);
  if(!seg)
    return -1;

  seg->seq  = actual_seq;
  seg->len  = actual_len;
  seg->next = *pp;
  memcpy(SEGMENT_DATA(seg),
         data + (actual_seq - seq),
         actual_len);

  *pp = seg;
  st->ooo_buf_size += actual_len;
  return 0;
}

/* ----------------------------------------------------------------
 * Helper: drain contiguous segments from the OOO list starting
 * at st->next_seq, delivering each one via the callback.
 * ---------------------------------------------------------------- */
static void drain_ooo(struct ndpi_tcp_reassembly *r,
                      u_int8_t direction)
{
  struct ndpi_tcp_stream  *st  = &r->streams[direction];
  struct ndpi_tcp_segment *seg = st->ooo_list;

  while(seg) {
    u_int32_t seg_end = seg->seq + seg->len;

    if(seg->seq == st->next_seq) {
      /* Segment is exactly at the expected position */
      deliver(r, direction, seg->seq, SEGMENT_DATA(seg), seg->len);
      st->next_seq     = seg_end;
      st->ooo_buf_size -= seg->len;
      st->ooo_list      = seg->next;
      ndpi_free(seg);
      seg = st->ooo_list;

    } else if(seq_lt(seg->seq, st->next_seq)) {
      if(seq_lt(st->next_seq, seg_end)) {
        /*
         * Segment overlaps next_seq from the left – deliver only the
         * portion we haven't seen yet.
         */
        u_int16_t skip    = (u_int16_t)(st->next_seq - seg->seq);
        u_int16_t deliver_len = (u_int16_t)(seg->len - skip);

        deliver(r, direction, st->next_seq,
                SEGMENT_DATA(seg) + skip, deliver_len);
        st->next_seq      = seg_end;
      }
      /* else: seg_end <= next_seq — segment is now entirely a
       * duplicate (next_seq advanced past it); just discard. */
      st->ooo_buf_size -= seg->len;
      st->ooo_list      = seg->next;
      ndpi_free(seg);
      seg = st->ooo_list;

    } else {
      /* seq > next_seq: gap still present – stop */
      break;
    }
  }
}

/* ================================================================
 * Public API
 * ================================================================ */

struct ndpi_tcp_reassembly *
ndpi_tcp_reassembly_alloc(u_int32_t max_ooo_buf_size,
                          ndpi_tcp_reassembly_cb_t callback,
                          void *userdata)
{
  struct ndpi_tcp_reassembly *r;

  r = (struct ndpi_tcp_reassembly *)ndpi_calloc(
        1, sizeof(struct ndpi_tcp_reassembly));
  if(!r)
    return NULL;

  r->max_ooo_buf_size = max_ooo_buf_size
                        ? max_ooo_buf_size
                        : NDPI_TCP_REASSEMBLY_DEFAULT_MAX_OOO_BUF;
  r->callback = callback;
  r->userdata = userdata;
  return r;
}

/* ---------------------------------------------------------------- */

void ndpi_tcp_reassembly_free(struct ndpi_tcp_reassembly *r)
{
  if(!r)
    return;

  free_ooo_list(&r->streams[0]);
  free_ooo_list(&r->streams[1]);
  ndpi_free(r);
}

/* ---------------------------------------------------------------- */

int ndpi_tcp_reassembly_process(struct ndpi_tcp_reassembly *r,
                                u_int8_t        direction,
                                u_int32_t       seq,
                                u_int8_t        syn,
                                const u_int8_t *payload,
                                u_int16_t       payload_len)
{
  struct ndpi_tcp_stream *st;
  u_int32_t              seq_end;

  if(!r || direction > 1)
    return -1;

  st = &r->streams[direction];

  /* SYN consumes one sequence number but carries no payload data */
  if(syn) {
    st->next_seq   = seq + 1;
    st->initialized = 1;
    /* Drop any stale OOO state from a previous connection */
    free_ooo_list(st);
    return 0;
  }

  if(payload_len == 0)
    return 0;

  seq_end = seq + payload_len;

  /* ---- First segment: initialise sequence tracking ---- */
  if(!st->initialized) {
    st->next_seq   = seq_end;
    st->initialized = 1;
    deliver(r, direction, seq, payload, payload_len);
    drain_ooo(r, direction);
    return 0;
  }

  /* ---- In-order segment ---- */
  if(seq == st->next_seq) {
    st->next_seq = seq_end;
    deliver(r, direction, seq, payload, payload_len);
    drain_ooo(r, direction);
    return 0;
  }

  /* ---- Retransmission / old data ---- */
  if(seq_leq(seq_end, st->next_seq)) {
    /*
     * The segment ends at or before next_seq: it is a pure
     * retransmission of data we have already delivered.
     */
    return 0;
  }

  /* ---- Partial overlap (retransmission with new tail) ---- */
  if(seq_lt(seq, st->next_seq) && seq_lt(st->next_seq, seq_end)) {
    /*
     * The segment's beginning overlaps data already delivered.
     * Deliver only the new tail.
     */
    u_int16_t skip    = (u_int16_t)(st->next_seq - seq);
    u_int16_t new_len = (u_int16_t)(payload_len - skip);

    st->next_seq = seq_end;
    deliver(r, direction, st->next_seq - new_len,
            payload + skip, new_len);
    drain_ooo(r, direction);
    return 0;
  }

  /* ---- Out-of-order segment ---- */
  return ooo_insert(st, seq, payload, payload_len,
                    r->max_ooo_buf_size);
}

/* ---------------------------------------------------------------- */

void ndpi_tcp_reassembly_get_stats(const struct ndpi_tcp_reassembly *r,
                                   u_int8_t direction,
                                   ndpi_tcp_reassembly_stats *stats)
{
  if(!r || direction > 1 || !stats)
    return;

  stats->next_seq       = r->streams[direction].next_seq;
  stats->ooo_buf_size   = r->streams[direction].ooo_buf_size;
  stats->ooo_seg_count  = 0;

  {
    const struct ndpi_tcp_segment *seg = r->streams[direction].ooo_list;
    while(seg) {
      stats->ooo_seg_count++;
      seg = seg->next;
    }
  }
}

/* ---------------------------------------------------------------- */

void ndpi_tcp_reassembly_reset(struct ndpi_tcp_reassembly *r,
                               u_int8_t direction)
{
  if(!r || direction > 1)
    return;

  free_ooo_list(&r->streams[direction]);
  r->streams[direction].next_seq    = 0;
  r->streams[direction].initialized = 0;
}

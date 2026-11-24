/*
 * Copyright (c) 2026 Bekei Park.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#undef NDEBUG
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "ct-dpif.h"
#include "dpif-provider.h"
#include "openvswitch/ofp-ct.h"
#include "ovstest.h"
#include "util.h"

/* A datapath that implements only what a partial match conntrack flush
 * needs: a dump of a fixed set of connections and a per-connection delete.
 *
 * The dump is a snapshot and the result of each delete is set by the test,
 * so a test can make a connection go away between the moment it is dumped
 * and the moment it is deleted, which no real datapath does on demand. */

#define N_CONNS 5
#define TEST_ZONE 7
#define FLUSH_MARK 0x1234
#define OTHER_MARK 0x4321
#define BASE_PORT 1000

struct test_conn {
    uint32_t mark;
    int flush_error;            /* Result of deleting this connection. */
    int n_flush;                /* Number of deletes of this connection. */
};

static struct test_conn conns[N_CONNS];

struct test_dump {
    struct ct_dpif_dump_state up;
    size_t pos;
};

static int
test_ct_dump_start(struct dpif *dpif OVS_UNUSED,
                   struct ct_dpif_dump_state **statep,
                   const uint16_t *zone, int *ptot_bkts OVS_UNUSED)
{
    struct test_dump *dump = xzalloc(sizeof *dump);

    ovs_assert(zone && *zone == TEST_ZONE);
    *statep = &dump->up;
    return 0;
}

static int
test_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                  struct ct_dpif_dump_state *state,
                  struct ct_dpif_entry *entry)
{
    struct test_dump *dump = CONTAINER_OF(state, struct test_dump, up);

    if (dump->pos >= N_CONNS) {
        return EOF;
    }

    memset(entry, 0, sizeof *entry);
    entry->zone = TEST_ZONE;
    entry->mark = conns[dump->pos].mark;
    entry->tuple_orig.l3_type = AF_INET;
    entry->tuple_orig.ip_proto = IPPROTO_TCP;
    entry->tuple_orig.src.ip = htonl(0x0a000001);
    entry->tuple_orig.dst.ip = htonl(0x0a000002);
    entry->tuple_orig.src_port = htons(BASE_PORT + dump->pos);
    entry->tuple_orig.dst_port = htons(80);
    dump->pos++;

    return 0;
}

static int
test_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                  struct ct_dpif_dump_state *state)
{
    free(CONTAINER_OF(state, struct test_dump, up));
    return 0;
}

static int
test_ct_flush(struct dpif *dpif OVS_UNUSED, const uint16_t *zone,
              const struct ct_dpif_tuple *tuple)
{
    size_t i;

    ovs_assert(zone && *zone == TEST_ZONE && tuple);
    i = ntohs(tuple->src_port) - BASE_PORT;
    ovs_assert(i < N_CONNS);

    conns[i].n_flush++;
    return conns[i].flush_error;
}

static const struct dpif_class test_dpif_class = {
    .type = "test-ct-dpif",
    .ct_dump_start = test_ct_dump_start,
    .ct_dump_next = test_ct_dump_next,
    .ct_dump_done = test_ct_dump_done,
    .ct_flush = test_ct_flush,
};

/* Flushes the connections with FLUSH_MARK in TEST_ZONE.  The delete of
 * connection 'i' returns 'flush_errors[i]'.  Checks that the flush returns
 * 'expected_error' and that the delete of connection 'i' was called
 * 'expected_flushes[i]' times.
 *
 * Connection 1 has another mark, so it must never be deleted. */
static void
check_flush(const char *name, const int flush_errors[N_CONNS],
            int expected_error, const int expected_flushes[N_CONNS])
{
    struct ofp_ct_match match = {
        .mark = FLUSH_MARK,
        .mark_mask = UINT32_MAX,
    };
    uint16_t zone = TEST_ZONE;
    struct dpif dpif;
    int error;

    for (size_t i = 0; i < N_CONNS; i++) {
        conns[i] = (struct test_conn) {
            .mark = i == 1 ? OTHER_MARK : FLUSH_MARK,
            .flush_error = flush_errors[i],
        };
    }

    dpif_init(&dpif, &test_dpif_class, "test", 0, 0);
    error = ct_dpif_flush(&dpif, &zone, &match);
    dpif_uninit(&dpif, false);

    if (error != expected_error) {
        ovs_fatal(0, "%s: flush returned %d (%s), expected %d (%s)", name,
                  error, ovs_strerror(error),
                  expected_error, ovs_strerror(expected_error));
    }
    for (size_t i = 0; i < N_CONNS; i++) {
        if (conns[i].n_flush != expected_flushes[i]) {
            ovs_fatal(0, "%s: connection %"PRIuSIZE" deleted %d times, "
                      "expected %d", name, i, conns[i].n_flush,
                      expected_flushes[i]);
        }
    }
    printf("%s: ok\n", name);
}

static void
test_ct_dpif_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    /* Every delete works: all the matching connections are deleted. */
    check_flush("all deleted",
                (const int[N_CONNS]) { 0, 0, 0, 0, 0 }, 0,
                (const int[N_CONNS]) { 1, 0, 1, 1, 1 });

    /* A connection that is gone by the time it is deleted does not stop the
     * flush and is not an error. */
    check_flush("gone in the middle",
                (const int[N_CONNS]) { 0, 0, ENOENT, 0, 0 }, 0,
                (const int[N_CONNS]) { 1, 0, 1, 1, 1 });
    check_flush("gone at the end",
                (const int[N_CONNS]) { 0, 0, 0, 0, ENOENT }, 0,
                (const int[N_CONNS]) { 1, 0, 1, 1, 1 });
    check_flush("all gone",
                (const int[N_CONNS]) { ENOENT, 0, ENOENT, ENOENT, ENOENT }, 0,
                (const int[N_CONNS]) { 1, 0, 1, 1, 1 });

    /* Any other error ends the flush and is returned. */
    check_flush("not supported",
                (const int[N_CONNS]) { 0, 0, EOPNOTSUPP, 0, 0 }, EOPNOTSUPP,
                (const int[N_CONNS]) { 1, 0, 1, 0, 0 });
    check_flush("gone, then no buffers",
                (const int[N_CONNS]) { ENOENT, 0, 0, ENOBUFS, 0 }, ENOBUFS,
                (const int[N_CONNS]) { 1, 0, 1, 1, 0 });
}

OVSTEST_REGISTER("test-ct-dpif", test_ct_dpif_main);

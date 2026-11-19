/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#include "tnl-neigh-cache.h"

#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>

#include "bitmap.h"
#include "cmap.h"
#include "coverage.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "errno.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-atomic.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "socket-util.h"
#include "timeval.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"


#define NEIGH_ENTRY_DEFAULT_IDLE_TIME_MS (15 * 60 * 1000)
#define NEIGH_ENTRY_MAX_AGING_TIME_S     3600
#define NEIGH_ENTRY_LOOKUP_RETRANS_TIME  1000

struct tnl_neigh_entry {
    struct cmap_node cmap_node;
    struct ovs_list refresh_node;
    struct in6_addr ip;
    struct in6_addr local_ip;   /* Local address seen on the learned port. */
    struct eth_addr mac;
    atomic_llong expires;       /* Expiration time in ms. */
    long long last_attempt;     /* LLONG_MIN until a probe is dequeued. */
    char br_name[IFNAMSIZ];
    char dev_name[IFNAMSIZ];    /* IP interface used to learn the neighbor. */
    atomic_bool complete;
};

static struct cmap table = CMAP_INITIALIZER;
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_list refresh_list OVS_GUARDED_BY(mutex)
    = OVS_LIST_INITIALIZER(&refresh_list);
static atomic_uint32_t neigh_aging;
static atomic_uint32_t neigh_retrans_time;
static atomic_llong next_event;

static uint32_t
tnl_neigh_hash(const struct in6_addr *ip)
{
    return hash_bytes(ip->s6_addr, 16, 0);
}

static bool
tnl_neigh_expired(struct tnl_neigh_entry *neigh)
{
    long long expires;

    atomic_read_relaxed(&neigh->expires, &expires);

    return expires <= time_msec();
}

static uint32_t
tnl_neigh_get_aging(void)
{
    unsigned int aging;

    atomic_read_relaxed(&neigh_aging, &aging);
    return aging;
}

static uint32_t
tnl_neigh_get_retrans_time(void)
{
    unsigned int retrans_time;

    atomic_read_relaxed(&neigh_retrans_time, &retrans_time);
    return retrans_time;
}

static void
tnl_neigh_schedule(long long deadline)
    OVS_REQUIRES(mutex)
{
    long long next;

    atomic_read_relaxed(&next_event, &next);
    if (deadline < next) {
        atomic_store_relaxed(&next_event, deadline);
    }
}

static long long
tnl_neigh_refresh_window(uint32_t retrans_time)
{
    /* Leave time for two retries when the intervals permit, but always give
     * a learned entry at least half its lifetime before probing again,
     * including when aging == retrans. */
    return MIN(3LL * retrans_time, tnl_neigh_get_aging() / 2);
}

static bool
tnl_neigh_is_complete(struct tnl_neigh_entry *neigh)
{
    bool complete;

    atomic_read_explicit(&neigh->complete, &complete, memory_order_acquire);
    return complete;
}

static struct tnl_neigh_entry *
tnl_neigh_lookup__(const char br_name[IFNAMSIZ], const struct in6_addr *dst)
{
    struct tnl_neigh_entry *neigh;
    uint32_t hash;

    hash = tnl_neigh_hash(dst);
    CMAP_FOR_EACH_WITH_HASH (neigh, cmap_node, hash, &table) {
        if (ipv6_addr_equals(&neigh->ip, dst) && !strcmp(neigh->br_name, br_name)) {
            if (tnl_neigh_expired(neigh)) {
                return NULL;
            }

            return neigh;
        }
    }
    return NULL;
}

static void
tnl_neigh_set_partial(const char name[IFNAMSIZ], const struct in6_addr *dst)
{
    ovs_mutex_lock(&mutex);
    long long expires = time_msec() + tnl_neigh_get_retrans_time();
    struct tnl_neigh_entry *neigh = tnl_neigh_lookup__(name, dst);
    if (neigh) {
        /* Entry inserted before lock taken. */

        ovs_mutex_unlock(&mutex);
        return;
    }
    neigh = xmalloc(sizeof *neigh);

    neigh->ip = *dst;
    neigh->local_ip = in6addr_any;
    atomic_store_relaxed(&neigh->complete, false);
    atomic_store_relaxed(&neigh->expires, expires);
    neigh->last_attempt = LLONG_MIN;
    ovs_strlcpy(neigh->br_name, name, sizeof neigh->br_name);
    neigh->dev_name[0] = '\0';
    ovs_list_init(&neigh->refresh_node);
    cmap_insert(&table, &neigh->cmap_node, tnl_neigh_hash(&neigh->ip));
    tnl_neigh_schedule(expires);

    ovs_mutex_unlock(&mutex);
    seq_change(tnl_conf_seq);
}

int
tnl_neigh_lookup(const char br_name[IFNAMSIZ], const struct in6_addr *dst,
                 struct eth_addr *mac, bool insert_partial)
{
    struct tnl_neigh_entry *neigh;
    int res = ENOENT;

    neigh = tnl_neigh_lookup__(br_name, dst);
    if (neigh) {
        if (tnl_neigh_is_complete(neigh)) {
            *mac = neigh->mac;
            res = 0;
        } else {
            res = EINPROGRESS;
        }
    } else if (insert_partial && tnl_neigh_get_retrans_time()) {
        /* Insert a partial entry only if there is a retransmit timer set. */
        tnl_neigh_set_partial(br_name, dst);
    }

    return res;
}

static void
neigh_entry_free(struct tnl_neigh_entry *neigh)
{
    free(neigh);
}

static void
tnl_neigh_cancel_refresh(struct tnl_neigh_entry *neigh)
    OVS_REQUIRES(mutex)
{
    if (!ovs_list_is_empty(&neigh->refresh_node)) {
        ovs_list_remove(&neigh->refresh_node);
        ovs_list_init(&neigh->refresh_node);
    }
}

static void
tnl_neigh_delete(struct tnl_neigh_entry *neigh)
    OVS_REQUIRES(mutex)
{
    uint32_t hash = tnl_neigh_hash(&neigh->ip);

    tnl_neigh_cancel_refresh(neigh);
    cmap_remove(&table, &neigh->cmap_node, hash);
    ovsrcu_postpone(neigh_entry_free, neigh);
}

void
tnl_neigh_set(const char name[IFNAMSIZ], const char dev_name[IFNAMSIZ],
              const struct in6_addr *dst, const struct eth_addr mac,
              const struct in6_addr *local_ip)
{
    ovs_mutex_lock(&mutex);
    long long expires = time_msec() + tnl_neigh_get_aging();
    struct tnl_neigh_entry *neigh = tnl_neigh_lookup__(name, dst);
    bool complete = neigh && tnl_neigh_is_complete(neigh);

    /* An unsolicited update may lack a local unicast address.  Keep the
     * previous one only if it belongs to the same learned interface. */
    struct in6_addr src = local_ip ? *local_ip : in6addr_any;
    if (!local_ip && neigh && dev_name && !strcmp(dev_name, neigh->dev_name)) {
        src = neigh->local_ip;
    }

    if (complete && !eth_addr_equals(neigh->mac, mac)) {
        tnl_neigh_delete(neigh);
        neigh = NULL;
        complete = false;
    }

    bool insert = !neigh;
    if (insert) {
        neigh = xmalloc(sizeof *neigh);
        neigh->ip = *dst;
        ovs_strlcpy(neigh->br_name, name, sizeof neigh->br_name);
        neigh->dev_name[0] = '\0';
        neigh->local_ip = in6addr_any;
        ovs_list_init(&neigh->refresh_node);
    } else {
        tnl_neigh_cancel_refresh(neigh);
    }

    if (dev_name && dev_name[0]) {
        ovs_strlcpy(neigh->dev_name, dev_name, sizeof neigh->dev_name);
        neigh->local_ip = src;
    }
    atomic_store_relaxed(&neigh->expires, expires);
    neigh->last_attempt = LLONG_MIN;
    long long window = tnl_neigh_refresh_window(tnl_neigh_get_retrans_time());
    tnl_neigh_schedule(expires - window);

    if (!complete) {
        neigh->mac = mac;
        /* Lockless readers can use the MAC once they see a complete entry. */
        atomic_store_explicit(&neigh->complete, true, memory_order_release);
        if (insert) {
            cmap_insert(&table, &neigh->cmap_node, tnl_neigh_hash(dst));
        }
    }
    ovs_mutex_unlock(&mutex);

    if (!complete) {
        seq_change(tnl_conf_seq);
    }
}

static int
tnl_arp_snoop(const struct flow *flow, struct flow_wildcards *wc,
              const char name[IFNAMSIZ], const char dev_name[IFNAMSIZ],
              bool allow_update)
{
    /* Snoop normal ARP replies and gratuitous ARP requests/replies only */
    if (!is_arp(flow)
        || (!is_garp(flow, wc) &&
            FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_proto) != ARP_OP_REPLY)
        || eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_sha))) {
        return EINVAL;
    }

    memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);

    if (allow_update) {
        struct in6_addr dst = in6_addr_mapped_ipv4(flow->nw_src);
        struct in6_addr local_ip = in6_addr_mapped_ipv4(flow->nw_dst);

        tnl_neigh_set(name, dev_name, &dst, flow->arp_sha,
                      flow->nw_src == flow->nw_dst ? NULL : &local_ip);
    }
    return 0;
}

static int
tnl_nd_snoop(const struct flow *flow, struct flow_wildcards *wc,
             const char name[IFNAMSIZ], const char dev_name[IFNAMSIZ],
             bool allow_update)
{
    if (!is_nd(flow, wc) || flow->tp_src != htons(ND_NEIGHBOR_ADVERT)) {
        return EINVAL;
    }
    /* - RFC4861 says Neighbor Advertisements sent in response to unicast Neighbor
     *   Solicitations SHOULD include the Target link-layer address. However, Linux
     *   doesn't. So, the response to Solicitations sent by OVS will include the
     *   TLL address and other Advertisements not including it can be ignored.
     * - OVS flow extract can set this field to zero in case of packet parsing errors.
     *   For details refer miniflow_extract()*/
    if (eth_addr_is_zero(FLOW_WC_GET_AND_MASK_WC(flow, wc, arp_tha))) {
        return EINVAL;
    }

    memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
    memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
    memset(&wc->masks.nd_target, 0xff, sizeof wc->masks.nd_target);

    if (allow_update) {
        tnl_neigh_set(name, dev_name, &flow->nd_target, flow->arp_tha,
                      ipv6_addr_is_multicast(&flow->ipv6_dst)
                      ? NULL : &flow->ipv6_dst);
    }
    return 0;
}

int
tnl_neigh_snoop(const struct flow *flow, struct flow_wildcards *wc,
                const char name[IFNAMSIZ], const char dev_name[IFNAMSIZ],
                bool allow_update)
{
    int res;
    res = tnl_arp_snoop(flow, wc, name, dev_name, allow_update);
    if (res != EINVAL) {
        return res;
    }
    return tnl_nd_snoop(flow, wc, name, dev_name, allow_update);
}

void
tnl_neigh_cache_run(void)
{
    struct tnl_neigh_entry *neigh;
    long long wakeup = LLONG_MAX;
    long long now = time_msec();
    long long scheduled;
    long long refresh_window;
    uint32_t retrans_time;
    bool changed = false;

    atomic_read_relaxed(&next_event, &scheduled);
    if (scheduled > now) {
        return;
    }

    ovs_mutex_lock(&mutex);
    retrans_time = tnl_neigh_get_retrans_time();
    refresh_window = tnl_neigh_refresh_window(retrans_time);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        long long expires;

        atomic_read_relaxed(&neigh->expires, &expires);
        if (expires <= now) {
            tnl_neigh_delete(neigh);
            changed = true;
            continue;
        }

        if (tnl_neigh_is_complete(neigh) && retrans_time
            && ovs_list_is_empty(&neigh->refresh_node)) {
            long long probe_at = neigh->last_attempt == LLONG_MIN
                                 ? expires - refresh_window
                                 : neigh->last_attempt + retrans_time;

            if (probe_at <= now) {
                ovs_list_push_back(&refresh_list, &neigh->refresh_node);
            } else {
                expires = MIN(expires, probe_at);
            }
        }
        wakeup = MIN(wakeup, expires);
    }
    atomic_store_relaxed(&next_event, wakeup);
    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

/* Dequeues a probe with the interface and local address from learning.
 * Returns false if no refresh is pending. */
bool
tnl_neigh_get_refresh(char br_name[IFNAMSIZ], char dev_name[IFNAMSIZ],
                      struct in6_addr *dst, struct in6_addr *local_ip)
    OVS_EXCLUDED(mutex)
{
    struct tnl_neigh_entry *neigh;
    bool found = false;

    ovs_mutex_lock(&mutex);
    while (!ovs_list_is_empty(&refresh_list)) {
        neigh = CONTAINER_OF(ovs_list_pop_front(&refresh_list),
                             struct tnl_neigh_entry, refresh_node);
        ovs_list_init(&neigh->refresh_node);
        if (tnl_neigh_expired(neigh)) {
            continue;
        }

        /* Space retries from the attempt, even if the probe waited in the
         * queue or the learned interface is temporarily unavailable. */
        neigh->last_attempt = time_msec();
        tnl_neigh_schedule(neigh->last_attempt + tnl_neigh_get_retrans_time());
        ovs_strlcpy(br_name, neigh->br_name, IFNAMSIZ);
        ovs_strlcpy(dev_name, neigh->dev_name, IFNAMSIZ);
        *dst = neigh->ip;
        *local_ip = neigh->local_ip;
        found = true;
        break;
    }
    ovs_mutex_unlock(&mutex);

    return found;
}

void
tnl_neigh_cache_wait(void)
{
    long long wakeup;

    atomic_read_relaxed(&next_event, &wakeup);
    if (wakeup != LLONG_MAX) {
        poll_timer_wait_until(wakeup);
    }
}

void
tnl_neigh_flush(const char br_name[IFNAMSIZ])
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH (neigh, cmap_node, &table) {
        if (!strcmp(neigh->br_name, br_name)) {
            tnl_neigh_delete(neigh);
            changed = true;
        }
    }
    ovs_mutex_unlock(&mutex);

    if (changed) {
        seq_change(tnl_conf_seq);
    }
}

static void
tnl_neigh_cache_flush(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct tnl_neigh_entry *neigh;
    bool changed = false;

    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        tnl_neigh_delete(neigh);
        changed = true;
    }
    ovs_mutex_unlock(&mutex);
    if (changed) {
        seq_change(tnl_conf_seq);
    }
    unixctl_command_reply(conn, "OK");
}

static void
tnl_neigh_cache_aging(struct unixctl_conn *conn, int argc,
                        const char *argv[], void *aux OVS_UNUSED)
{
    long long int new_exp, curr_exp;
    struct tnl_neigh_entry *neigh;
    uint32_t aging;

    if (argc == 1) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        ds_put_format(&ds, "%"PRIu32, tnl_neigh_get_aging() / 1000);
        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);

        return;
    }

    if (!ovs_scan(argv[1], "%"SCNu32, &aging) ||
        !aging || aging > NEIGH_ENTRY_MAX_AGING_TIME_S) {
        unixctl_command_reply_error(conn, "bad aging value");
        return;
    }

    aging *= 1000;

    if (aging < tnl_neigh_get_retrans_time()) {
        unixctl_command_reply_error(conn, "aging value cannot be less than "
                                          "retrans_time");
        return;
    }

    if (aging == tnl_neigh_get_aging()) {
        unixctl_command_reply(conn, "OK");
        return;
    }

    ovs_mutex_lock(&mutex);
    atomic_store_relaxed(&neigh_aging, aging);
    new_exp = time_msec() + aging;
    CMAP_FOR_EACH (neigh, cmap_node, &table) {
        atomic_read_relaxed(&neigh->expires, &curr_exp);
        if (new_exp < curr_exp) {
            atomic_store_relaxed(&neigh->expires, new_exp);
        }
        tnl_neigh_cancel_refresh(neigh);
    }
    if (!cmap_is_empty(&table)) {
        tnl_neigh_schedule(time_msec());
    }
    ovs_mutex_unlock(&mutex);

    unixctl_command_reply(conn, "OK");
}

static void
tnl_neigh_cache_retrans_time(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED)
{
    long long int new_exp, curr_exp;
    struct tnl_neigh_entry *neigh;
    uint32_t retrans_time;

    if (argc == 1) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        ds_put_format(&ds, "%"PRIu32, tnl_neigh_get_retrans_time());
        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);

        return;
    }

    /* Zero retransmit value is acceptable. */
    if (!ovs_scan(argv[1], "%"SCNu32, &retrans_time)) {
        unixctl_command_reply_error(conn, "bad retrans_time value");
        return;
    } else if (retrans_time > tnl_neigh_get_aging()) {
        unixctl_command_reply_error(conn, "retrans_time value cannot be "
                                          "greater than aging");
        return;
    }

    if (retrans_time == tnl_neigh_get_retrans_time()) {
        unixctl_command_reply(conn, "OK");
        return;
    }

    ovs_mutex_lock(&mutex);
    atomic_store_relaxed(&neigh_retrans_time, retrans_time);
    new_exp = time_msec() + retrans_time;
    CMAP_FOR_EACH (neigh, cmap_node, &table) {
        atomic_read_relaxed(&neigh->expires, &curr_exp);
        if (!tnl_neigh_is_complete(neigh) && new_exp < curr_exp) {
            atomic_store_relaxed(&neigh->expires, new_exp);
        }
        tnl_neigh_cancel_refresh(neigh);
        if (!retrans_time) {
            neigh->last_attempt = LLONG_MIN;
        }
    }
    if (!cmap_is_empty(&table)) {
        tnl_neigh_schedule(time_msec());
    }
    ovs_mutex_unlock(&mutex);

    unixctl_command_reply(conn, "OK");
}

static int
lookup_any(const char *host_name, struct in6_addr *address)
{
    if (addr_is_ipv6(host_name)) {
        return lookup_ipv6(host_name, address);
    } else {
        int r;
        struct in_addr ip;
        r = lookup_ip(host_name, &ip);
        if (r == 0) {
            in6_addr_set_mapped_ipv4(address, ip.s_addr);
        }
        return r;
    }
    return ENOENT;
}

static void
tnl_neigh_cache_add(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[], void *aux OVS_UNUSED)
{
    const char *br_name = argv[1];
    struct eth_addr mac;
    struct in6_addr ip6;

    if (lookup_any(argv[2], &ip6) != 0) {
        unixctl_command_reply_error(conn, "bad IP address");
        return;
    }

    if (!eth_addr_from_string(argv[3], &mac)) {
        unixctl_command_reply_error(conn, "bad MAC address");
        return;
    }

    tnl_neigh_set(br_name, NULL, &ip6, mac, NULL);
    unixctl_command_reply(conn, "OK");
}

static void
tnl_neigh_cache_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct tnl_neigh_entry *neigh;

    ds_put_cstr(&ds, "IP                                            MAC                 Bridge\n");
    ds_put_cstr(&ds, "==========================================================================\n");
    ovs_mutex_lock(&mutex);
    CMAP_FOR_EACH(neigh, cmap_node, &table) {
        int start_len, need_ws;

        start_len = ds.length;
        ipv6_format_mapped(&neigh->ip, &ds);

        need_ws = INET6_ADDRSTRLEN - (ds.length - start_len);
        ds_put_char_multiple(&ds, ' ', need_ws);

        if (tnl_neigh_is_complete(neigh)) {
            ds_put_format(&ds, ETH_ADDR_FMT"   %s",
                          ETH_ADDR_ARGS(neigh->mac), neigh->br_name);
        } else {
            ds_put_format(&ds, "                    %s INCOMPLETE",
                          neigh->br_name);
        }
        if (tnl_neigh_expired(neigh)) {
            ds_put_cstr(&ds, " STALE");
        } else if (neigh->last_attempt != LLONG_MIN
                   || !ovs_list_is_empty(&neigh->refresh_node)) {
            ds_put_cstr(&ds, " REFRESHING");
        }
        ds_put_char(&ds, '\n');

    }
    ovs_mutex_unlock(&mutex);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
tnl_neigh_cache_init(void)
{
    atomic_init(&neigh_aging, NEIGH_ENTRY_DEFAULT_IDLE_TIME_MS);
    atomic_init(&neigh_retrans_time, NEIGH_ENTRY_LOOKUP_RETRANS_TIME);
    atomic_init(&next_event, LLONG_MAX);
    unixctl_command_register("tnl/arp/show", "", 0, 0,
                             tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/arp/set", "BRIDGE IP MAC", 3, 3,
                             tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/arp/flush", "", 0, 0,
                             tnl_neigh_cache_flush, NULL);
    unixctl_command_register("tnl/arp/aging", "[SECS]", 0, 1,
                             tnl_neigh_cache_aging, NULL);
    unixctl_command_register("tnl/neigh/show", "", 0, 0,
                             tnl_neigh_cache_show, NULL);
    unixctl_command_register("tnl/neigh/set", "BRIDGE IP MAC", 3, 3,
                             tnl_neigh_cache_add, NULL);
    unixctl_command_register("tnl/neigh/flush", "", 0, 0,
                             tnl_neigh_cache_flush, NULL);
    unixctl_command_register("tnl/neigh/aging", "[SECS]", 0, 1,
                             tnl_neigh_cache_aging, NULL);
    unixctl_command_register("tnl/neigh/retrans_time", "[MSECS]", 0, 1,
                             tnl_neigh_cache_retrans_time, NULL);
}

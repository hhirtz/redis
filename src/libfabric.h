#pragma once

#include <arpa/inet.h>
#include <rdma/fi_eq.h>

void print_fi_error(const char *fn, const char *msg, int err);

/** Wait for the first item in the given event queue */
int eq_wait(struct fid_eq *const eq);

/** Wait for the first item in the given completion queue */
int cq_wait(struct fid_cq *const cq, struct fi_cq_msg_entry *res);

// TODO changer le nom de la fonction pck c pas un lookup c'est plus convertir
// addr en out d'après l'av
int lookup_sa(struct sockaddr_in *const out, struct fid_av *const av, fi_addr_t addr);

int repeat_send(struct fid_ep *const e, void *const buf, size_t const len, fi_addr_t to);

struct state {
    struct fi_info *fi, *root_fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_eq *events;
    struct fid_cq *completions;
    struct fid_av *addresses;
    struct fid_ep *endpoint;
    void *local_addr;
    size_t local_addr_len;
};

/** Initialize the given state.
 *
 * Returns 0 on success or a negative integer on error.
 */
int state_create(struct state *const s, char const *const port);
void state_destroy(struct state *const s);

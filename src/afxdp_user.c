/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "../libbpf/src/libbpf.h"
#include "../libbpf/src/xsk.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX
#define MAX_CPUS 64

struct xsk_umem_info 
{
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info
{
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx;
};

struct thread_info
{
    int id;
    struct xsk_socket_info *xsk;
};

const struct option opts[] =
{
    {"dev", required_argument, NULL, 'i'},
    {"sockets", required_argument, NULL, 'c'},
    {"skb", no_argument, NULL, 's'},
    {NULL, 0, NULL, 0}
};

static int cont = 1;
static int progfd;
uint32_t xdp_flags = XDP_FLAGS_DRV_MODE;

void ShutDown(int tmp)
{
    cont = 0;
}

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
    r->cached_cons = *r->consumer + r->size;
    return r->cached_cons - r->cached_prod;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
    {
        return NULL;
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                    NULL);
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int rxqueue, int ifidx, const char *dev)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    uint32_t prog_id = 0;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags = xdp_flags;
    xsk_cfg.bind_flags = XDP_COPY;
    ret = xsk_socket__create(&xsk_info->xsk, dev, rxqueue, umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);

    if (ret)
        goto error_exit;

    ret = bpf_get_link_xdp_id(ifidx, &prog_id, XDP_FLAGS_DRV_MODE);

    if (ret)
        goto error_exit;

    /* Initialize umem frame allocation */

    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                        XSK_RING_PROD__DEFAULT_NUM_DESCS,
                        &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        goto error_exit;

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
            xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&xsk_info->umem->fq,
                    XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

error_exit:
    errno = -ret;
    return NULL;
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}


struct bpf_object *load_bpf_object_file__simple(const char *filename)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);

    if (err)
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Num => %d\n", filename, strerror(-err), err);
    }

    progfd = first_prog_fd;

    return obj;
}

static int xdp_detach(int ifindex, uint32_t xdp_flags)
{
    int err;

    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    if (err < 0)
    {
        fprintf(stderr, "Error detaching XDP program. Error => %s. Error Num => %.d\n", strerror(-err), err);

        return -1;
    }

    return EXIT_SUCCESS;
}

static int xdp_attach(int ifindex, uint32_t xdp_flags, int prog_fd)
{
    int err;
    
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);

    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        
        uint32_t oldflags = xdp_flags;

        xdp_flags &= ~XDP_FLAGS_MODES;
        xdp_flags |= (oldflags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

        err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

        if (!err)
        {
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, oldflags);
        }
    }

    if (err < 0)
    {
        fprintf(stderr, "Error attaching XDP program. Error => %s. Error Num => %d. IfIndex => %d.\n", strerror(-err), -err, ifindex);

        switch(-err)
        {
            case EBUSY:

            case EEXIST:
            {
                xdp_detach(ifindex, xdp_flags);
                fprintf(stderr, "Additional: XDP already loaded on device.\n");
                break;
            }

            case EOPNOTSUPP:
                fprintf(stderr, "Additional: XDP-native nor SKB not supported? Not sure how that's possible.\n");

                break;

            default:
                break;
        }

        return -1;
    }

    return EXIT_SUCCESS;
}

void *PollXSK(void *data)
{
    struct thread_info *ti = (struct thread_info *)data;

    struct pollfd fds[2];
    int ret, nfds = 1;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(ti->xsk->xsk);
    fds[0].events = POLLIN;

    while (cont)
    {
        ret = poll(fds, nfds, -1);

        if (ret <= 0 || ret > 1)
            continue;

        uint32_t idx_rx = 0;

        unsigned int rcvd = xsk_ring_cons__peek(&ti->xsk->rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd)
            continue;

        fprintf(stdout, "Received packet from AF_XDP socket from queue ID %d\n", ti->id);
    }

	xsk_socket__delete(ti->xsk->xsk);
	xsk_umem__delete(ti->xsk->umem->umem);
    free(ti);

    pthread_exit(NULL);
}

static inline unsigned int bpf_num_possible_cpus(void)
{
    static const char *fcpu = "/sys/devices/system/cpu/possible";
    unsigned int start, end, possible_cpus = 0;
    char buff[128];
    FILE *fp;
    int n;

    fp = fopen(fcpu, "r");

    if (!fp) 
    {
        printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
        exit(1);
    }

    while (fgets(buff, sizeof(buff), fp)) 
    {
        n = sscanf(buff, "%u-%u", &start, &end);

        if (n == 0) 
        {
            printf("Failed to retrieve # possible CPUs!\n");
            exit(1);
        } 
        else if (n == 1) 
        {
            end = start;
        }

        possible_cpus = start == 0 ? end + 1 : 0;
        break;
    }

    fclose(fp);

    return possible_cpus;
}

int main(int argc, char **argv)
{
    int ret;
    int ifidx;
    int xsks_map_fd;
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *bpf_obj = NULL;

    int cpus = bpf_num_possible_cpus();
    char *dev = "ens18";

    int c = -1;
    while (optind < argc)
    {
        if ((c = getopt_long(argc, argv, "i:c:s", opts, NULL)) != -1)
        {
            switch (c)
            {
                case 'i':
                    dev = optarg;

                    break;

                case 'c':
                    cpus = atoi(optarg);

                    break;

                case 's':
                    xdp_flags = XDP_FLAGS_SKB_MODE;

                    break;
            }
        }
        else
        {
            optind++;
        }
    }

    ifidx = if_nametoindex(dev);

    if (ifidx < 1)
    {
        fprintf(stderr, "Error finding device: %s\n", dev);

        exit(EXIT_FAILURE);
    }

    /* Global shutdown handler */
    signal(SIGINT, ShutDown);

    xdp_detach(ifidx, xdp_flags);

    /* Load custom program if configured */
    struct bpf_map *map;

    bpf_obj = load_bpf_object_file__simple("src/afxdp_kern.o");

    if (!bpf_obj) 
    {
        fprintf(stderr, "Error opening BPF object file.");

        exit(EXIT_FAILURE);
    }

    if (xdp_attach(ifidx, xdp_flags, progfd) != 0)
    {
        fprintf(stderr, "Error attaching XDP program: %s\n", strerror(errno));

        exit(EXIT_FAILURE);
    }

    /* We also need to load the xsks_map */
    map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");

    xsks_map_fd = bpf_map__fd(map);

    if (xsks_map_fd < 0) 
    {
        fprintf(stderr, "ERROR: no xsks map found: %s\n", strerror(xsks_map_fd));

        exit(EXIT_FAILURE);
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) 
    {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));

        exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) 
    {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));

        exit(EXIT_FAILURE);
    }

    struct xsk_umem_info *umem[MAX_CPUS];
    struct xsk_socket_info *xsk_socket[MAX_CPUS];

    for (int i = 0; i < cpus; i++)
    {
        /* Initialize shared packet_buffer for umem usage */
        umem[i] = configure_xsk_umem(packet_buffer, packet_buffer_size);

        if (umem[i] == NULL) 
        {
            fprintf(stderr, "ERROR: Can't create umem \"%s\"\n", strerror(errno));
            
            continue;
        }

        /* Open and configure the AF_XDP (xsk) socket */
        xsk_socket[i] = xsk_configure_socket(umem[i], i, ifidx, (const char *)dev);

        if (xsk_socket[i] == NULL) 
        {
            fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n", strerror(errno));
            
            continue;
        }

        struct thread_info *ti = malloc(sizeof(struct thread_info));

        ti->id = i;
        ti->xsk = xsk_socket[i];

        pthread_t tid;

        pthread_create(&tid, NULL, PollXSK, (void *)ti);

        fprintf(stdout, "Created thread %d\n", i);
    }

    fprintf(stdout, "Starting program...\n");

    while (cont)
    {
        sleep(1);
    }

    /* Cleanup */
    xdp_detach(ifidx, xdp_flags);

    for (int i = 0; i < cpus; i++)
    {
        if (xsk_socket[i] != NULL)
        {
            xsk_socket__delete(xsk_socket[i]->xsk);
        }

        if (umem[i] != NULL)
        {
            xsk_umem__delete(umem[i]->umem);
        }
    }

    return EXIT_SUCCESS;
}

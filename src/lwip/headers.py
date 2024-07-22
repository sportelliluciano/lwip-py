LWIP_HEADERS = """
void sys_check_core_locking(void);
void lwip_example_app_platform_assert(const char *msg, int line, const char *file);
struct netif *custom_ip4_route_src_hook(const void *src, const void *dest);
extern unsigned int lwip_port_rand(void);
struct sio_status_s;
typedef struct sio_status_s sio_status_t;
typedef unsigned int sys_prot_t;
typedef long int ptrdiff_t;
typedef long unsigned int size_t;
typedef int wchar_t;
typedef struct {
  long long __max_align_ll ;
  long double __max_align_ld ;
} max_align_t;
typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uintptr_t mem_ptr_t;
typedef int ssize_t;
u16_t lwip_htons(u16_t x);
u32_t lwip_htonl(u32_t x);
void lwip_itoa(char* result, size_t bufsize, int number);
int lwip_strnicmp(const char* str1, const char* str2, size_t len);
int lwip_stricmp(const char* str1, const char* str2);
char* lwip_strnstr(const char* buffer, const char* token, size_t n);
char* lwip_strnistr(const char* buffer, const char* token, size_t n);
int lwip_memcmp_consttime(const void* s1, const void* s2, size_t len);
struct ip4_addr {
  u32_t addr;
};
typedef struct ip4_addr ip4_addr_t;
struct netif;
u8_t ip4_addr_isbroadcast_u32(u32_t addr, const struct netif *netif);
u8_t ip4_addr_netmask_valid(u32_t netmask);
u32_t ipaddr_addr(const char *cp);
int ip4addr_aton(const char *cp, ip4_addr_t *addr);
char *ip4addr_ntoa(const ip4_addr_t *addr);
char *ip4addr_ntoa_r(const ip4_addr_t *addr, char *buf, int buflen);
enum lwip_ipv6_scope_type
{
  IP6_UNKNOWN = 0,
  IP6_UNICAST = 1,
  IP6_MULTICAST = 2
};
struct ip6_addr {
  u32_t addr[4];
  u8_t zone;
};
typedef struct ip6_addr ip6_addr_t;
int ip6addr_aton(const char *cp, ip6_addr_t *addr);
char *ip6addr_ntoa(const ip6_addr_t *addr);
char *ip6addr_ntoa_r(const ip6_addr_t *addr, char *buf, int buflen);
enum lwip_ip_addr_type {
  IPADDR_TYPE_V4 = 0U,
  IPADDR_TYPE_V6 = 6U,
  IPADDR_TYPE_ANY = 46U
};
typedef struct ip_addr {
  union {
    ip6_addr_t ip6;
    ip4_addr_t ip4;
  } u_addr;
  u8_t type;
} ip_addr_t;
extern const ip_addr_t ip_addr_any_type;
char *ipaddr_ntoa(const ip_addr_t *addr);
char *ipaddr_ntoa_r(const ip_addr_t *addr, char *buf, int buflen);
int ipaddr_aton(const char *cp, ip_addr_t *addr);
extern const ip_addr_t ip_addr_any;
extern const ip_addr_t ip_addr_broadcast;
extern const ip_addr_t ip6_addr_any;
typedef u32_t in_addr_t;
struct in_addr {
  in_addr_t s_addr;
};
struct in6_addr {
  union {
    u32_t u32_addr[4];
    u8_t u8_addr[16];
  } un;
};
extern const struct in6_addr in6addr_any;
void lwip_init(void);
typedef enum {
  ERR_OK = 0,
  ERR_MEM = -1,
  ERR_BUF = -2,
  ERR_TIMEOUT = -3,
  ERR_RTE = -4,
  ERR_INPROGRESS = -5,
  ERR_VAL = -6,
  ERR_WOULDBLOCK = -7,
  ERR_USE = -8,
  ERR_ALREADY = -9,
  ERR_ISCONN = -10,
  ERR_CONN = -11,
  ERR_IF = -12,
  ERR_ABRT = -13,
  ERR_RST = -14,
  ERR_CLSD = -15,
  ERR_ARG = -16
} err_enum_t;
typedef s8_t err_t;
int err_to_errno(err_t err);
typedef enum {
  PBUF_TRANSPORT = 0 + (14 + 0) + 40 + 20,
  PBUF_IP = 0 + (14 + 0) + 40,
  PBUF_LINK = 0 + (14 + 0),
  PBUF_RAW_TX = 0,
  PBUF_RAW = 0
} pbuf_layer;
typedef enum {
  PBUF_RAM = (0x0200 | 0x80 | 0x00),
  PBUF_ROM = 0x01,
  PBUF_REF = (0x40 | 0x01),
  PBUF_POOL = (0x0100 | 0x80 | 0x02)
} pbuf_type;
struct pbuf {
  struct pbuf *next;
  void *payload;
  u16_t tot_len;
  u16_t len;
  u8_t type_internal;
  u8_t flags;
  u8_t ref;
  u8_t if_idx;
 
};
struct pbuf_rom {
  struct pbuf *next;
  const void *payload;
};
typedef void (*pbuf_free_custom_fn)(struct pbuf *p);
struct pbuf_custom {
  struct pbuf pbuf;
  pbuf_free_custom_fn custom_free_function;
};
struct pbuf *pbuf_alloc(pbuf_layer l, u16_t length, pbuf_type type);
struct pbuf *pbuf_alloc_reference(void *payload, u16_t length, pbuf_type type);
struct pbuf *pbuf_alloced_custom(pbuf_layer l, u16_t length, pbuf_type type,
                                 struct pbuf_custom *p, void *payload_mem,
                                 u16_t payload_mem_len);
void pbuf_realloc(struct pbuf *p, u16_t size);
u8_t pbuf_header(struct pbuf *p, s16_t header_size);
u8_t pbuf_header_force(struct pbuf *p, s16_t header_size);
u8_t pbuf_add_header(struct pbuf *p, size_t header_size_increment);
u8_t pbuf_add_header_force(struct pbuf *p, size_t header_size_increment);
u8_t pbuf_remove_header(struct pbuf *p, size_t header_size);
struct pbuf *pbuf_free_header(struct pbuf *q, u16_t size);
void pbuf_ref(struct pbuf *p);
u8_t pbuf_free(struct pbuf *p);
u16_t pbuf_clen(const struct pbuf *p);
void pbuf_cat(struct pbuf *head, struct pbuf *tail);
void pbuf_chain(struct pbuf *head, struct pbuf *tail);
struct pbuf *pbuf_dechain(struct pbuf *p);
err_t pbuf_copy(struct pbuf *p_to, const struct pbuf *p_from);
err_t pbuf_copy_partial_pbuf(struct pbuf *p_to, const struct pbuf *p_from, u16_t copy_len, u16_t offset);
u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset);
void *pbuf_get_contiguous(const struct pbuf *p, void *buffer, size_t bufsize, u16_t len, u16_t offset);
err_t pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len);
err_t pbuf_take_at(struct pbuf *buf, const void *dataptr, u16_t len, u16_t offset);
struct pbuf *pbuf_skip(struct pbuf* in, u16_t in_offset, u16_t* out_offset);
struct pbuf *pbuf_coalesce(struct pbuf *p, pbuf_layer layer);
struct pbuf *pbuf_clone(pbuf_layer l, pbuf_type type, struct pbuf *p);
u8_t pbuf_get_at(const struct pbuf* p, u16_t offset);
int pbuf_try_get_at(const struct pbuf* p, u16_t offset);
void pbuf_put_at(struct pbuf* p, u16_t offset, u8_t data);
u16_t pbuf_memcmp(const struct pbuf* p, u16_t offset, const void* s2, u16_t n);
u16_t pbuf_memfind(const struct pbuf* p, const void* mem, u16_t mem_len, u16_t start_offset);
u16_t pbuf_strstr(const struct pbuf* p, const char* substr);
typedef u16_t mem_size_t;
void mem_init(void);
void *mem_trim(void *mem, mem_size_t size);
void *mem_malloc(mem_size_t size);
void *mem_calloc(mem_size_t count, mem_size_t size);
void mem_free(void *mem);





















typedef enum {
MEMP_RAW_PCB,
MEMP_UDP_PCB,
MEMP_TCP_PCB,
MEMP_TCP_PCB_LISTEN,
MEMP_TCP_SEG,
MEMP_ALTCP_PCB,
MEMP_REASSDATA,
MEMP_FRAG_PBUF,
MEMP_NETBUF,
MEMP_NETCONN,
MEMP_TCPIP_MSG_API,
MEMP_TCPIP_MSG_INPKT,
MEMP_ARP_QUEUE,
MEMP_IGMP_GROUP,
MEMP_SYS_TIMEOUT,
MEMP_NETDB,
MEMP_ND6_QUEUE,
MEMP_IP6_REASSDATA,
MEMP_MLD6_GROUP,
MEMP_PBUF,
MEMP_PBUF_POOL,
  MEMP_MAX
} memp_t;
struct memp {
  struct memp *next;
};
struct memp_desc {
  const char *desc;
  struct stats_mem *stats;
  u16_t size;
  u16_t num;
  u8_t *base;
  struct memp **tab;
};
void memp_init_pool(const struct memp_desc *desc);
void *memp_malloc_pool(const struct memp_desc *desc);
void memp_free_pool(const struct memp_desc* desc, void *mem);
extern const struct memp_desc* const memp_pools[MEMP_MAX];
void memp_init(void);
void *memp_malloc(memp_t type);
void memp_free(memp_t type, void *mem);
struct stats_proto {
  u16_t xmit;
  u16_t recv;
  u16_t fw;
  u16_t drop;
  u16_t chkerr;
  u16_t lenerr;
  u16_t memerr;
  u16_t rterr;
  u16_t proterr;
  u16_t opterr;
  u16_t err;
  u16_t cachehit;
};
struct stats_igmp {
  u16_t xmit;
  u16_t recv;
  u16_t drop;
  u16_t chkerr;
  u16_t lenerr;
  u16_t memerr;
  u16_t proterr;
  u16_t rx_v1;
  u16_t rx_group;
  u16_t rx_general;
  u16_t rx_report;
  u16_t tx_join;
  u16_t tx_leave;
  u16_t tx_report;
};
struct stats_mem {
  const char *name;
  u16_t err;
  mem_size_t avail;
  mem_size_t used;
  mem_size_t max;
  u16_t illegal;
};
struct stats_syselem {
  u16_t used;
  u16_t max;
  u16_t err;
};
struct stats_sys {
  struct stats_syselem sem;
  struct stats_syselem mutex;
  struct stats_syselem mbox;
};
struct stats_mib2 {
  u32_t ipinhdrerrors;
  u32_t ipinaddrerrors;
  u32_t ipinunknownprotos;
  u32_t ipindiscards;
  u32_t ipindelivers;
  u32_t ipoutrequests;
  u32_t ipoutdiscards;
  u32_t ipoutnoroutes;
  u32_t ipreasmoks;
  u32_t ipreasmfails;
  u32_t ipfragoks;
  u32_t ipfragfails;
  u32_t ipfragcreates;
  u32_t ipreasmreqds;
  u32_t ipforwdatagrams;
  u32_t ipinreceives;
  u32_t ip6reasmoks;
  u32_t tcpactiveopens;
  u32_t tcppassiveopens;
  u32_t tcpattemptfails;
  u32_t tcpestabresets;
  u32_t tcpoutsegs;
  u32_t tcpretranssegs;
  u32_t tcpinsegs;
  u32_t tcpinerrs;
  u32_t tcpoutrsts;
  u32_t udpindatagrams;
  u32_t udpnoports;
  u32_t udpinerrors;
  u32_t udpoutdatagrams;
  u32_t icmpinmsgs;
  u32_t icmpinerrors;
  u32_t icmpindestunreachs;
  u32_t icmpintimeexcds;
  u32_t icmpinparmprobs;
  u32_t icmpinsrcquenchs;
  u32_t icmpinredirects;
  u32_t icmpinechos;
  u32_t icmpinechoreps;
  u32_t icmpintimestamps;
  u32_t icmpintimestampreps;
  u32_t icmpinaddrmasks;
  u32_t icmpinaddrmaskreps;
  u32_t icmpoutmsgs;
  u32_t icmpouterrors;
  u32_t icmpoutdestunreachs;
  u32_t icmpouttimeexcds;
  u32_t icmpoutechos;
  u32_t icmpoutechoreps;
};
struct stats_mib2_netif_ctrs {
  u32_t ifinoctets;
  u32_t ifinucastpkts;
  u32_t ifinnucastpkts;
  u32_t ifindiscards;
  u32_t ifinerrors;
  u32_t ifinunknownprotos;
  u32_t ifoutoctets;
  u32_t ifoutucastpkts;
  u32_t ifoutnucastpkts;
  u32_t ifoutdiscards;
  u32_t ifouterrors;
};
struct stats_ {
  struct stats_proto link;
  struct stats_proto etharp;
  struct stats_proto ip_frag;
  struct stats_proto ip;
  struct stats_proto icmp;
  struct stats_igmp igmp;
  struct stats_proto udp;
  struct stats_proto tcp;
  struct stats_mem mem;
  struct stats_mem *memp[MEMP_MAX];
  struct stats_sys sys;
  struct stats_proto ip6;
  struct stats_proto icmp6;
  struct stats_proto ip6_frag;
  struct stats_igmp mld6;
  struct stats_proto nd6;
};
extern struct stats_ lwip_stats;
void stats_init(void);
void stats_display(void);
void stats_display_proto(struct stats_proto *proto, const char *name);
void stats_display_igmp(struct stats_igmp *igmp, const char *name);
void stats_display_mem(struct stats_mem *mem, const char *name);
void stats_display_memp(struct stats_mem *mem, int index);
void stats_display_sys(struct stats_sys *sys);
enum lwip_internal_netif_client_data_index
{
   LWIP_NETIF_CLIENT_DATA_INDEX_DHCP,
   LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP,
   LWIP_NETIF_CLIENT_DATA_INDEX_ACD,
   LWIP_NETIF_CLIENT_DATA_INDEX_IGMP,
   LWIP_NETIF_CLIENT_DATA_INDEX_MLD6,
   LWIP_NETIF_CLIENT_DATA_INDEX_MAX
};
struct netif;
enum netif_mac_filter_action {
  NETIF_DEL_MAC_FILTER = 0,
  NETIF_ADD_MAC_FILTER = 1
};
typedef err_t (*netif_init_fn)(struct netif *netif);
typedef err_t (*netif_input_fn)(struct pbuf *p, struct netif *inp);
typedef err_t (*netif_output_fn)(struct netif *netif, struct pbuf *p,
       const ip4_addr_t *ipaddr);
typedef err_t (*netif_output_ip6_fn)(struct netif *netif, struct pbuf *p,
       const ip6_addr_t *ipaddr);
typedef err_t (*netif_linkoutput_fn)(struct netif *netif, struct pbuf *p);
typedef void (*netif_status_callback_fn)(struct netif *netif);
typedef err_t (*netif_igmp_mac_filter_fn)(struct netif *netif,
       const ip4_addr_t *group, enum netif_mac_filter_action action);
typedef err_t (*netif_mld_mac_filter_fn)(struct netif *netif,
       const ip6_addr_t *group, enum netif_mac_filter_action action);
u8_t netif_alloc_client_data_id(void);
typedef u8_t netif_addr_idx_t;
struct netif {
  struct netif *next;
  ip_addr_t ip_addr;
  ip_addr_t netmask;
  ip_addr_t gw;
  ip_addr_t ip6_addr[3];
  u8_t ip6_addr_state[3];
  u32_t ip6_addr_valid_life[3];
  u32_t ip6_addr_pref_life[3];
  netif_input_fn input;
  netif_output_fn output;
  netif_linkoutput_fn linkoutput;
  netif_output_ip6_fn output_ip6;
  netif_status_callback_fn status_callback;
  netif_status_callback_fn link_callback;
  void *state;
  void* client_data[LWIP_NETIF_CLIENT_DATA_INDEX_MAX + (1)];
  u16_t mtu;
  u16_t mtu6;
  u8_t hwaddr[6U];
  u8_t hwaddr_len;
  u8_t flags;
  char name[2];
  u8_t num;
  u8_t ip6_autoconfig_enabled;
  u8_t rs_count;
  netif_igmp_mac_filter_fn igmp_mac_filter;
  netif_mld_mac_filter_fn mld_mac_filter;
  struct acd *acd_list;
  struct pbuf *loop_first;
  struct pbuf *loop_last;
  u16_t loop_cnt_current;
  u8_t reschedule_poll;
};
extern struct netif *netif_list;
extern struct netif *netif_default;
void netif_init(void);
struct netif *netif_add_noaddr(struct netif *netif, void *state, netif_init_fn init, netif_input_fn input);
struct netif *netif_add(struct netif *netif,
                            const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
                            void *state, netif_init_fn init, netif_input_fn input);
void netif_set_addr(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t *netmask,
                    const ip4_addr_t *gw);
void netif_remove(struct netif * netif);
struct netif *netif_find(const char *name);
void netif_set_default(struct netif *netif);
void netif_set_ipaddr(struct netif *netif, const ip4_addr_t *ipaddr);
void netif_set_netmask(struct netif *netif, const ip4_addr_t *netmask);
void netif_set_gw(struct netif *netif, const ip4_addr_t *gw);
void netif_set_up(struct netif *netif);
void netif_set_down(struct netif *netif);
void netif_set_status_callback(struct netif *netif, netif_status_callback_fn status_callback);
void netif_set_link_up(struct netif *netif);
void netif_set_link_down(struct netif *netif);
void netif_set_link_callback(struct netif *netif, netif_status_callback_fn link_callback);
err_t netif_loop_output(struct netif *netif, struct pbuf *p);
void netif_poll(struct netif *netif);
err_t netif_input(struct pbuf *p, struct netif *inp);
void netif_ip6_addr_set(struct netif *netif, s8_t addr_idx, const ip6_addr_t *addr6);
void netif_ip6_addr_set_parts(struct netif *netif, s8_t addr_idx, u32_t i0, u32_t i1, u32_t i2, u32_t i3);
void netif_ip6_addr_set_state(struct netif* netif, s8_t addr_idx, u8_t state);
s8_t netif_get_ip6_addr_match(struct netif *netif, const ip6_addr_t *ip6addr);
void netif_create_ip6_linklocal_address(struct netif *netif, u8_t from_mac_48bit);
err_t netif_add_ip6_address(struct netif *netif, const ip6_addr_t *ip6addr, s8_t *chosen_idx);
u8_t netif_name_to_index(const char *name);
char * netif_index_to_name(u8_t idx, char *name);
struct netif* netif_get_by_index(u8_t idx);
typedef u16_t netif_nsc_reason_t;
typedef union
{
  struct link_changed_s
  {
    u8_t state;
  } link_changed;
  struct status_changed_s
  {
    u8_t state;
  } status_changed;
  struct ipv4_changed_s
  {
    const ip_addr_t* old_address;
    const ip_addr_t* old_netmask;
    const ip_addr_t* old_gw;
  } ipv4_changed;
  struct ipv6_set_s
  {
    s8_t addr_index;
    const ip_addr_t* old_address;
  } ipv6_set;
  struct ipv6_addr_state_changed_s
  {
    s8_t addr_index;
    u8_t old_state;
    const ip_addr_t* address;
  } ipv6_addr_state_changed;
} netif_ext_callback_args_t;
typedef void (*netif_ext_callback_fn)(struct netif* netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t* args);
struct netif_ext_callback;
typedef struct netif_ext_callback
{
  netif_ext_callback_fn callback_fn;
  struct netif_ext_callback* next;
} netif_ext_callback_t;
void netif_add_ext_callback(netif_ext_callback_t* callback, netif_ext_callback_fn fn);
void netif_remove_ext_callback(netif_ext_callback_t* callback);
void netif_invoke_ext_callback(struct netif* netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t* args);
typedef u8_t sa_family_t;
typedef u16_t in_port_t;
struct sockaddr_in {
  u8_t sin_len;
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
};
struct sockaddr_in6 {
  u8_t sin6_len;
  sa_family_t sin6_family;
  in_port_t sin6_port;
  u32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  u32_t sin6_scope_id;
};
struct sockaddr {
  u8_t sa_len;
  sa_family_t sa_family;
  char sa_data[14];
};
struct sockaddr_storage {
  u8_t s2_len;
  sa_family_t ss_family;
  char s2_data1[2];
  u32_t s2_data2[3];
  u32_t s2_data3[3];
};
typedef u32_t socklen_t;
struct iovec {
  void *iov_base;
  size_t iov_len;
};
typedef int msg_iovlen_t;
struct msghdr {
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  msg_iovlen_t msg_iovlen;
  void *msg_control;
  socklen_t msg_controllen;
  int msg_flags;
};
struct cmsghdr {
  socklen_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
};
struct ifreq {
  char ifr_name[6];
};
struct linger {
  int l_onoff;
  int l_linger;
};
typedef struct ip_mreq {
    struct in_addr imr_multiaddr;
    struct in_addr imr_interface;
} ip_mreq;
struct in_pktinfo {
  unsigned int ipi_ifindex;
  struct in_addr ipi_addr;
};
typedef struct ipv6_mreq {
  struct in6_addr ipv6mr_multiaddr;
  unsigned int ipv6mr_interface;
} ipv6_mreq;
typedef struct fd_set
{
  unsigned char fd_bits [(12 +7)/8];
} fd_set;
typedef unsigned int nfds_t;
struct pollfd
{
  int fd;
  short events;
  short revents;
};
void lwip_socket_thread_init(void);
void lwip_socket_thread_cleanup(void);
int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
 int lwip_close(int s);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
ssize_t lwip_recv(int s, void *mem, size_t len, int flags);
ssize_t lwip_read(int s, void *mem, size_t len);
ssize_t lwip_readv(int s, const struct iovec *iov, int iovcnt);
ssize_t lwip_recvfrom(int s, void *mem, size_t len, int flags,
      struct sockaddr *from, socklen_t *fromlen);
ssize_t lwip_recvmsg(int s, struct msghdr *message, int flags);
ssize_t lwip_send(int s, const void *dataptr, size_t size, int flags);
ssize_t lwip_sendmsg(int s, const struct msghdr *message, int flags);
ssize_t lwip_sendto(int s, const void *dataptr, size_t size, int flags,
    const struct sockaddr *to, socklen_t tolen);
int lwip_socket(int domain, int type, int protocol);
ssize_t lwip_write(int s, const void *dataptr, size_t size);
ssize_t lwip_writev(int s, const struct iovec *iov, int iovcnt);
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
                struct timeval *timeout);
int lwip_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int lwip_ioctl(int s, long cmd, void *argp);
int lwip_fcntl(int s, int cmd, int val);
const char *lwip_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int lwip_inet_pton(int af, const char *src, void *dst);
struct sys_sem;
typedef struct sys_sem * sys_sem_t;
struct sys_mutex;
typedef struct sys_mutex * sys_mutex_t;
struct sys_mbox;
typedef struct sys_mbox * sys_mbox_t;
struct sys_thread;
typedef struct sys_thread * sys_thread_t;
int lwip_unix_keypressed(void);
void sys_mark_tcpip_thread(void);
void sys_lock_tcpip_core(void);
void sys_unlock_tcpip_core(void);
typedef void (*lwip_thread_fn)(void *arg);
err_t sys_mutex_new(sys_mutex_t *mutex);
void sys_mutex_lock(sys_mutex_t *mutex);
void sys_mutex_unlock(sys_mutex_t *mutex);
void sys_mutex_free(sys_mutex_t *mutex);
err_t sys_sem_new(sys_sem_t *sem, u8_t count);
void sys_sem_signal(sys_sem_t *sem);
u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout);
void sys_sem_free(sys_sem_t *sem);
void sys_msleep(u32_t ms);
err_t sys_mbox_new(sys_mbox_t *mbox, int size);
void sys_mbox_post(sys_mbox_t *mbox, void *msg);
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg);
err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg);
u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout);
u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg);
void sys_mbox_free(sys_mbox_t *mbox);
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio);
void sys_init(void);
u32_t sys_jiffies(void);
u32_t sys_now(void);
sys_prot_t sys_arch_protect(void);
void sys_arch_unprotect(sys_prot_t pval);
typedef u16_t tcpwnd_size_t;
enum tcp_state {
  CLOSED = 0,
  LISTEN = 1,
  SYN_SENT = 2,
  SYN_RCVD = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1 = 5,
  FIN_WAIT_2 = 6,
  CLOSE_WAIT = 7,
  CLOSING = 8,
  LAST_ACK = 9,
  TIME_WAIT = 10
};
const char* tcp_debug_state_str(enum tcp_state s);

struct ip4_addr_packed {
  u32_t addr;
} ;

typedef struct ip4_addr_packed ip4_addr_p_t;

struct ip_hdr {
  u8_t _v_hl;
  u8_t _tos;
  u16_t _len;
  u16_t _id;
  u16_t _offset;
  u8_t _ttl;
  u8_t _proto;
  u16_t _chksum;
  ip4_addr_p_t src;
  ip4_addr_p_t dest;
} ;

struct netif *ip4_route(const ip4_addr_t *dest);
struct netif *ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest);
err_t ip4_input(struct pbuf *p, struct netif *inp);
err_t ip4_output(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto);
err_t ip4_output_if(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto, struct netif *netif);
err_t ip4_output_if_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto, struct netif *netif);
err_t ip4_output_if_opt(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
       u16_t optlen);
err_t ip4_output_if_opt_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
       u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
       u16_t optlen);
void ip4_set_default_multicast_netif(struct netif* default_multicast_netif);

struct ip6_addr_packed {
  u32_t addr[4];
} ;

typedef struct ip6_addr_packed ip6_addr_p_t;

struct ip6_hdr {
  u32_t _v_tc_fl;
  u16_t _plen;
  u8_t _nexth;
  u8_t _hoplim;
  ip6_addr_p_t src;
  ip6_addr_p_t dest;
} ;


struct ip6_opt_hdr {
  u8_t _opt_type;
  u8_t _opt_dlen;
} ;


struct ip6_hbh_hdr {
  u8_t _nexth;
  u8_t _hlen;
} ;


struct ip6_dest_hdr {
  u8_t _nexth;
  u8_t _hlen;
} ;


struct ip6_rout_hdr {
  u8_t _nexth;
  u8_t _hlen;
  u8_t _routing_type;
  u8_t _segments_left;
} ;


struct ip6_frag_hdr {
  u8_t _nexth;
  u8_t reserved;
  u16_t _fragment_offset;
  u32_t _identification;
} ;

struct netif *ip6_route(const ip6_addr_t *src, const ip6_addr_t *dest);
const ip_addr_t *ip6_select_source_address(struct netif *netif, const ip6_addr_t * dest);
err_t ip6_input(struct pbuf *p, struct netif *inp);
err_t ip6_output(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
                         u8_t hl, u8_t tc, u8_t nexth);
err_t ip6_output_if(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
                            u8_t hl, u8_t tc, u8_t nexth, struct netif *netif);
err_t ip6_output_if_src(struct pbuf *p, const ip6_addr_t *src, const ip6_addr_t *dest,
                            u8_t hl, u8_t tc, u8_t nexth, struct netif *netif);
err_t ip6_options_add_hbh_ra(struct pbuf * p, u8_t nexth, u8_t value);
struct ip_pcb {
  ip_addr_t local_ip; ip_addr_t remote_ip; u8_t netif_idx; u8_t so_options; u8_t tos; u8_t ttl ;
};
struct ip_globals
{
  struct netif *current_netif;
  struct netif *current_input_netif;
  const struct ip_hdr *current_ip4_header;
  struct ip6_hdr *current_ip6_header;
  u16_t current_ip_header_tot_len;
  ip_addr_t current_iphdr_src;
  ip_addr_t current_iphdr_dest;
};
extern struct ip_globals ip_data;
err_t ip_input(struct pbuf *p, struct netif *inp);

struct icmp_hdr {
  u8_t type;
  u8_t code;
  u16_t chksum;
  u32_t data;
} ;


struct icmp_echo_hdr {
  u8_t type;
  u8_t code;
  u16_t chksum;
  u16_t id;
  u16_t seqno;
} ;

enum icmp6_type {
  ICMP6_TYPE_DUR = 1,
  ICMP6_TYPE_PTB = 2,
  ICMP6_TYPE_TE = 3,
  ICMP6_TYPE_PP = 4,
  ICMP6_TYPE_PE1 = 100,
  ICMP6_TYPE_PE2 = 101,
  ICMP6_TYPE_RSV_ERR = 127,
  ICMP6_TYPE_EREQ = 128,
  ICMP6_TYPE_EREP = 129,
  ICMP6_TYPE_MLQ = 130,
  ICMP6_TYPE_MLR = 131,
  ICMP6_TYPE_MLD = 132,
  ICMP6_TYPE_RS = 133,
  ICMP6_TYPE_RA = 134,
  ICMP6_TYPE_NS = 135,
  ICMP6_TYPE_NA = 136,
  ICMP6_TYPE_RD = 137,
  ICMP6_TYPE_MRA = 151,
  ICMP6_TYPE_MRS = 152,
  ICMP6_TYPE_MRT = 153,
  ICMP6_TYPE_PE3 = 200,
  ICMP6_TYPE_PE4 = 201,
  ICMP6_TYPE_RSV_INF = 255
};
enum icmp6_dur_code {
  ICMP6_DUR_NO_ROUTE = 0,
  ICMP6_DUR_PROHIBITED = 1,
  ICMP6_DUR_SCOPE = 2,
  ICMP6_DUR_ADDRESS = 3,
  ICMP6_DUR_PORT = 4,
  ICMP6_DUR_POLICY = 5,
  ICMP6_DUR_REJECT_ROUTE = 6
};
enum icmp6_te_code {
  ICMP6_TE_HL = 0,
  ICMP6_TE_FRAG = 1
};
enum icmp6_pp_code {
  ICMP6_PP_FIELD = 0,
  ICMP6_PP_HEADER = 1,
  ICMP6_PP_OPTION = 2
};

struct icmp6_hdr {
  u8_t type;
  u8_t code;
  u16_t chksum;
  u32_t data;
} ;


struct icmp6_echo_hdr {
  u8_t type;
  u8_t code;
  u16_t chksum;
  u16_t id;
  u16_t seqno;
} ;

void icmp6_input(struct pbuf *p, struct netif *inp);
void icmp6_dest_unreach(struct pbuf *p, enum icmp6_dur_code c);
void icmp6_packet_too_big(struct pbuf *p, u32_t mtu);
void icmp6_time_exceeded(struct pbuf *p, enum icmp6_te_code c);
void icmp6_time_exceeded_with_addrs(struct pbuf *p, enum icmp6_te_code c,
    const ip6_addr_t *src_addr, const ip6_addr_t *dest_addr);
void icmp6_param_problem(struct pbuf *p, enum icmp6_pp_code c, const void *pointer);
enum icmp_dur_type {
  ICMP_DUR_NET = 0,
  ICMP_DUR_HOST = 1,
  ICMP_DUR_PROTO = 2,
  ICMP_DUR_PORT = 3,
  ICMP_DUR_FRAG = 4,
  ICMP_DUR_SR = 5
};
enum icmp_te_type {
  ICMP_TE_TTL = 0,
  ICMP_TE_FRAG = 1
};
void icmp_input(struct pbuf *p, struct netif *inp);
void icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t);
struct tcp_pcb;
struct tcp_pcb_listen;
typedef err_t (*tcp_accept_fn)(void *arg, struct tcp_pcb *newpcb, err_t err);
typedef err_t (*tcp_recv_fn)(void *arg, struct tcp_pcb *tpcb,
                             struct pbuf *p, err_t err);
typedef err_t (*tcp_sent_fn)(void *arg, struct tcp_pcb *tpcb,
                              u16_t len);
typedef err_t (*tcp_poll_fn)(void *arg, struct tcp_pcb *tpcb);
typedef void (*tcp_err_fn)(void *arg, err_t err);
typedef err_t (*tcp_connected_fn)(void *arg, struct tcp_pcb *tpcb, err_t err);
typedef void (*tcp_extarg_callback_pcb_destroyed_fn)(u8_t id, void *data);
typedef err_t (*tcp_extarg_callback_passive_open_fn)(u8_t id, struct tcp_pcb_listen *lpcb, struct tcp_pcb *cpcb);
struct tcp_ext_arg_callbacks {
  tcp_extarg_callback_pcb_destroyed_fn destroy;
  tcp_extarg_callback_passive_open_fn passive_open;
};
typedef u16_t tcpflags_t;
struct tcp_pcb_listen {
  ip_addr_t local_ip; ip_addr_t remote_ip; u8_t netif_idx; u8_t so_options; u8_t tos; u8_t ttl ;
  struct tcp_pcb_listen *next; void *callback_arg; enum tcp_state state; u8_t prio; u16_t local_port;
  tcp_accept_fn accept;
  u8_t backlog;
  u8_t accepts_pending;
};
struct tcp_pcb {
  ip_addr_t local_ip; ip_addr_t remote_ip; u8_t netif_idx; u8_t so_options; u8_t tos; u8_t ttl ;
  struct tcp_pcb *next; void *callback_arg; enum tcp_state state; u8_t prio; u16_t local_port;
  u16_t remote_port;
  tcpflags_t flags;
  u8_t polltmr, pollinterval;
  u8_t last_timer;
  u32_t tmr;
  u32_t rcv_nxt;
  tcpwnd_size_t rcv_wnd;
  tcpwnd_size_t rcv_ann_wnd;
  u32_t rcv_ann_right_edge;
  s16_t rtime;
  u16_t mss;
  u32_t rttest;
  u32_t rtseq;
  s16_t sa, sv;
  s16_t rto;
  u8_t nrtx;
  u8_t dupacks;
  u32_t lastack;
  tcpwnd_size_t cwnd;
  tcpwnd_size_t ssthresh;
  u32_t rto_end;
  u32_t snd_nxt;
  u32_t snd_wl1, snd_wl2;
  u32_t snd_lbb;
  tcpwnd_size_t snd_wnd;
  tcpwnd_size_t snd_wnd_max;
  tcpwnd_size_t snd_buf;
  u16_t snd_queuelen;
  u16_t unsent_oversize;
  tcpwnd_size_t bytes_acked;
  struct tcp_seg *unsent;
  struct tcp_seg *unacked;
  struct tcp_seg *ooseq;
  struct pbuf *refused_data;
  struct tcp_pcb_listen* listener;
  tcp_sent_fn sent;
  tcp_recv_fn recv;
  tcp_connected_fn connected;
  tcp_poll_fn poll;
  tcp_err_fn errf;
  u32_t keep_idle;
  u8_t persist_cnt;
  u8_t persist_backoff;
  u8_t persist_probe;
  u8_t keep_cnt_sent;
};
struct tcp_pcb * tcp_new (void);
struct tcp_pcb * tcp_new_ip_type (u8_t type);
void tcp_arg (struct tcp_pcb *pcb, void *arg);
void tcp_recv (struct tcp_pcb *pcb, tcp_recv_fn recv);
void tcp_sent (struct tcp_pcb *pcb, tcp_sent_fn sent);
void tcp_err (struct tcp_pcb *pcb, tcp_err_fn err);
void tcp_accept (struct tcp_pcb *pcb, tcp_accept_fn accept);
void tcp_poll (struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval);
void tcp_backlog_delayed(struct tcp_pcb* pcb);
void tcp_backlog_accepted(struct tcp_pcb* pcb);
void tcp_recved (struct tcp_pcb *pcb, u16_t len);
err_t tcp_bind (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                              u16_t port);
void tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif);
err_t tcp_connect (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                              u16_t port, tcp_connected_fn connected);
struct tcp_pcb * tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err);
struct tcp_pcb * tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog);
void tcp_abort (struct tcp_pcb *pcb);
err_t tcp_close (struct tcp_pcb *pcb);
err_t tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx);
err_t tcp_write (struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                              u8_t apiflags);
void tcp_setprio (struct tcp_pcb *pcb, u8_t prio);
err_t tcp_output (struct tcp_pcb *pcb);
err_t tcp_tcp_get_tcp_addrinfo(struct tcp_pcb *pcb, int local, ip_addr_t *addr, u16_t *port);
typedef void (* lwip_cyclic_timer_handler)(void);
struct lwip_cyclic_timer {
  u32_t interval_ms;
  lwip_cyclic_timer_handler handler;
};
extern const struct lwip_cyclic_timer lwip_cyclic_timers[];
extern const int lwip_num_cyclic_timers;
typedef void (* sys_timeout_handler)(void *arg);
struct sys_timeo {
  struct sys_timeo *next;
  u32_t time;
  sys_timeout_handler h;
  void *arg;
};
void sys_timeouts_init(void);
void sys_timeout(u32_t msecs, sys_timeout_handler handler, void *arg);
void sys_untimeout(sys_timeout_handler handler, void *arg);
void sys_restart_timeouts(void);
void sys_check_timeouts(void);
u32_t sys_timeouts_sleeptime(void);
extern sys_mutex_t lock_tcpip_core;
struct pbuf;
struct netif;
typedef void (*tcpip_init_done_fn)(void *arg);
typedef void (*tcpip_callback_fn)(void *ctx);
struct tcpip_callback_msg;
void tcpip_init(tcpip_init_done_fn tcpip_init_done, void *arg);
err_t tcpip_inpkt(struct pbuf *p, struct netif *inp, netif_input_fn input_fn);
err_t tcpip_input(struct pbuf *p, struct netif *inp);
err_t tcpip_try_callback(tcpip_callback_fn function, void *ctx);
err_t tcpip_callback(tcpip_callback_fn function, void *ctx);
err_t tcpip_callback_wait(tcpip_callback_fn function, void *ctx);
struct tcpip_callback_msg* tcpip_callbackmsg_new(tcpip_callback_fn function, void *ctx);
void tcpip_callbackmsg_delete(struct tcpip_callback_msg* msg);
err_t tcpip_callbackmsg_trycallback(struct tcpip_callback_msg* msg);
err_t tcpip_callbackmsg_trycallback_fromisr(struct tcpip_callback_msg* msg);
err_t pbuf_free_callback(struct pbuf *p);
err_t mem_free_callback(void *m);

struct udp_hdr {
  u16_t src;
  u16_t dest;
  u16_t len;
  u16_t chksum;
} ;

struct udp_pcb;
typedef void (*udp_recv_fn)(void *arg, struct udp_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr, u16_t port);
struct udp_pcb {
  ip_addr_t local_ip; ip_addr_t remote_ip; u8_t netif_idx; u8_t so_options; u8_t tos; u8_t ttl ;
  struct udp_pcb *next;
  u8_t flags;
  u16_t local_port, remote_port;
  ip4_addr_t mcast_ip4;
  u8_t mcast_ifindex;
  u8_t mcast_ttl;
  u16_t chksum_len_rx, chksum_len_tx;
  udp_recv_fn recv;
  void *recv_arg;
};
extern struct udp_pcb *udp_pcbs;
struct udp_pcb * udp_new (void);
struct udp_pcb * udp_new_ip_type(u8_t type);
void udp_remove (struct udp_pcb *pcb);
err_t udp_bind (struct udp_pcb *pcb, const ip_addr_t *ipaddr,
                                 u16_t port);
void udp_bind_netif (struct udp_pcb *pcb, const struct netif* netif);
err_t udp_connect (struct udp_pcb *pcb, const ip_addr_t *ipaddr,
                                 u16_t port);
void udp_disconnect (struct udp_pcb *pcb);
void udp_recv (struct udp_pcb *pcb, udp_recv_fn recv,
                                 void *recv_arg);
err_t udp_sendto_if (struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif);
err_t udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, const ip_addr_t *src_ip);
err_t udp_sendto (struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port);
err_t udp_send (struct udp_pcb *pcb, struct pbuf *p);
void udp_input (struct pbuf *p, struct netif *inp);
void udp_init (void);
void udp_netif_ip_addr_changed(const ip_addr_t* old_addr, const ip_addr_t* new_addr);
enum lwip_ieee_eth_type {
  ETHTYPE_IP = 0x0800U,
  ETHTYPE_ARP = 0x0806U,
  ETHTYPE_WOL = 0x0842U,
  ETHTYPE_RARP = 0x8035U,
  ETHTYPE_VLAN = 0x8100U,
  ETHTYPE_IPV6 = 0x86DDU,
  ETHTYPE_PPPOEDISC = 0x8863U,
  ETHTYPE_PPPOE = 0x8864U,
  ETHTYPE_JUMBO = 0x8870U,
  ETHTYPE_PROFINET = 0x8892U,
  ETHTYPE_ETHERCAT = 0x88A4U,
  ETHTYPE_LLDP = 0x88CCU,
  ETHTYPE_SERCOS = 0x88CDU,
  ETHTYPE_MRP = 0x88E3U,
  ETHTYPE_PTP = 0x88F7U,
  ETHTYPE_QINQ = 0x9100U
};

struct eth_addr {
  u8_t addr[6];
} ;


struct eth_hdr {
  struct eth_addr dest;
  struct eth_addr src;
  u16_t type;
} ;


struct eth_vlan_hdr {
  u16_t prio_vid;
  u16_t tpid;
} ;


struct ip4_addr_wordaligned {
  u16_t addrw[2];
} ;


struct etharp_hdr {
  u16_t hwtype;
  u16_t proto;
  u8_t hwlen;
  u8_t protolen;
  u16_t opcode;
  struct eth_addr shwaddr;
  struct ip4_addr_wordaligned sipaddr;
  struct eth_addr dhwaddr;
  struct ip4_addr_wordaligned dipaddr;
} ;

enum etharp_opcode {
  ARP_REQUEST = 1,
  ARP_REPLY = 2
};
struct etharp_q_entry {
  struct etharp_q_entry *next;
  struct pbuf *p;
};
void etharp_tmr(void);
ssize_t etharp_find_addr(struct netif *netif, const ip4_addr_t *ipaddr,
         struct eth_addr **eth_ret, const ip4_addr_t **ip_ret);
int etharp_get_entry(size_t i, ip4_addr_t **ipaddr, struct netif **netif, struct eth_addr **eth_ret);
err_t etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);
err_t etharp_query(struct netif *netif, const ip4_addr_t *ipaddr, struct pbuf *q);
err_t etharp_request(struct netif *netif, const ip4_addr_t *ipaddr);
void etharp_cleanup_netif(struct netif *netif);
err_t etharp_acd_probe(struct netif *netif, const ip4_addr_t *ipaddr);
err_t etharp_acd_announce(struct netif *netif, const ip4_addr_t *ipaddr);
void etharp_input(struct pbuf *p, struct netif *netif);
err_t ethernet_input(struct pbuf *p, struct netif *netif);
err_t ethernet_output(struct netif* netif, struct pbuf* p, const struct eth_addr* src, const struct eth_addr* dst, u16_t eth_type);
extern const struct eth_addr ethbroadcast, ethzero;
typedef struct netif *(*ip4_route_hook_fn)(const void *src, const void *dest);
void set_ip4_route_fn_override(ip4_route_hook_fn fn);
extern int errno;
"""

#ifndef _COMPAT_H_
#define _COMPAT_H_

#include "lwip/netif.h"

typedef struct netif *(*ip4_route_hook_fn)(const void *src, const void *dest);

void set_ip4_route_fn_override(ip4_route_hook_fn fn);

#endif // _COMPAT_H_
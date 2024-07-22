#include <stdio.h>
#include <stdlib.h>

#include "lwip/netif.h"
#include "compat.h"

static ip4_route_hook_fn ip4_route_override = NULL;

struct netif *custom_ip4_route_src_hook(const void *src, const void *dest)
{
  if (ip4_route_override)
  {
    return ip4_route_override(src, dest);
  }

  return NULL;
}

/* This function is only required to prevent arch.h including stdio.h
 * (which it does if LWIP_PLATFORM_ASSERT is undefined)
 */
void lwip_example_app_platform_assert(const char *msg, int line, const char *file)
{
  printf("Assertion \"%s\" failed at line %d in %s\n", msg, line, file);
  fflush(NULL);
  abort();
}

void set_ip4_route_fn_override(ip4_route_hook_fn fn)
{
  ip4_route_override = fn;
}
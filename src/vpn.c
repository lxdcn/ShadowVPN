/**
  vpn.c

  Copyright (C) 2015 clowwindy

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

// TODO we want to put shadowvpn.h at the bottom of the imports
// but TARGET_* is defined in config.h
#include "shadowvpn.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if_tun.h>

#define tun_read(...) read(__VA_ARGS__)
#define tun_write(...) write(__VA_ARGS__)

int vpn_tun_alloc(const char *dev) {
  struct ifreq ifr;
  int fd, e;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    err("open");
    errf("can not open /dev/net/tun");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if(*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((e = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    err("ioctl[TUNSETIFF]");
    errf("can not setup tun device: %s", dev);
    close(fd);
    return -1;
  }
  // strcpy(dev, ifr.ifr_name);
  return fd;
}


int vpn_udp_alloc(int if_bind, const char *host, int port,
                  struct sockaddr *addr, socklen_t* addrlen) {
  struct addrinfo hints;
  struct addrinfo *res;
  int sock, r, flags;

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) {
    errf("getaddrinfo: %s", gai_strerror(r));
    return -1;
  }

  if (res->ai_family == AF_INET)
    ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
  else if (res->ai_family == AF_INET6)
    ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
  else {
    errf("unknown ai_family %d", res->ai_family);
    freeaddrinfo(res);
    return -1;
  }
  memcpy(addr, res->ai_addr, res->ai_addrlen);
  *addrlen = res->ai_addrlen;

  if (-1 == (sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP))) {
    err("socket");
    errf("can not create socket");
    freeaddrinfo(res);
    return -1;
  }

  if (if_bind) {
    if (0 != bind(sock, res->ai_addr, res->ai_addrlen)) {
      err("bind");
      errf("can not bind %s:%d", host, port);
      close(sock);
      freeaddrinfo(res);
      return -1;
    }
  }
  freeaddrinfo(res);

  flags = fcntl(sock, F_GETFL, 0);
  if (flags != -1) {
    if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
      return sock;
  }
  err("fcntl");

  close(sock);
  return -1;
}

static int max(int a, int b) {
  return a > b ? a : b;
}

int vpn_ctx_init(vpn_ctx_t *ctx, shadowvpn_args_t *args) {
  int i;

  bzero(ctx, sizeof(vpn_ctx_t));
  ctx->remote_addrp = (struct sockaddr *)&ctx->remote_addr;

  if (-1 == pipe(ctx->control_pipe)) {
    err("pipe");
    return -1;
  }
  if (-1 == (ctx->tun = vpn_tun_alloc(args->intf))) {
    errf("failed to create tun device");
    return -1;
  }

  ctx->nsock = 1;
  ctx->socks = calloc(ctx->nsock, sizeof(int));
  for (i = 0; i < ctx->nsock; i++) {
    int *sock = ctx->socks + i;
    if (-1 == (*sock = vpn_udp_alloc(args->mode == SHADOWVPN_MODE_SERVER,
                                     args->server, args->port,
                                     ctx->remote_addrp,
                                     &ctx->remote_addrlen))) {
      errf("failed to create UDP socket");
      close(ctx->tun);
      return -1;
    }
  }
  ctx->args = args;
  return 0;
}

int vpn_run(vpn_ctx_t *ctx) {
  fd_set readset;
  int max_fd = 0, i;
  ssize_t r;
  if (ctx->running) {
    errf("can not start, already running");
    return -1;
  }

  ctx->running = 1;

  shell_up(ctx->args);

  ctx->tun_buf = malloc(ctx->args->mtu);
  ctx->udp_buf = malloc(ctx->args->mtu);
  bzero(ctx->tun_buf, ctx->args->mtu);
  bzero(ctx->udp_buf, ctx->args->mtu);
  

  logf("VPN started");

  while (ctx->running) {
    FD_ZERO(&readset);
    FD_SET(ctx->control_pipe[0], &readset);
    FD_SET(ctx->tun, &readset);

    max_fd = 0;
    for (i = 0; i < ctx->nsock; i++) {
      FD_SET(ctx->socks[i], &readset);
      max_fd = max(max_fd, ctx->socks[i]);
    }

    // we assume that pipe fd is always less than tun and sock fd which are
    // created later
    max_fd = max(ctx->tun, max_fd) + 1;

    if (-1 == select(max_fd, &readset, NULL, NULL, NULL)) {
      if (errno == EINTR)
        continue;
      err("select");
      break;
    }

    if (FD_ISSET(ctx->control_pipe[0], &readset)) {
      char pipe_buf;
      (void)read(ctx->control_pipe[0], &pipe_buf, 1);
      break;
    }

    if (FD_ISSET(ctx->tun, &readset)) {
      r = tun_read(ctx->tun, ctx->tun_buf, ctx->args->mtu);
      logf("Read from tun %d bytes", r);
      if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // do nothing
        } else if (errno == EPERM || errno == EINTR) {
          // just log, do nothing
          err("read from tun");
        } else {
          err("read from tun");
          break;
        }
      }

      if (ctx->remote_addrlen) {

        // TODO concurrency is currently removed
        int sock_to_send = ctx->socks[0];

        logf("Writing to UDP %d bytes ...", r);
        r = sendto(sock_to_send, ctx->tun_buf, r, 0, ctx->remote_addrp, ctx->remote_addrlen);
        if (r == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // do nothing
          } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                     errno == EPERM || errno == EINTR || errno == EMSGSIZE) {
            // just log, do nothing
            err("sendto");
          } else {
            err("sendto");
            // TODO rebuild socket
            break;
          }
        }
      }
    }
    for (i = 0; i < ctx->nsock; i++) {
      int sock = ctx->socks[i];
      if (FD_ISSET(sock, &readset)) {
        // only change remote addr if decryption succeeds
        struct sockaddr_storage temp_remote_addr;
        socklen_t temp_remote_addrlen = sizeof(temp_remote_addr);
        r = recvfrom(sock, ctx->udp_buf, ctx->args->mtu, 0,
                    (struct sockaddr *)&temp_remote_addr,
                    &temp_remote_addrlen);
        logf("Read UDP %d bytes", r);
        if (r == -1) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // do nothing
          } else if (errno == ENETUNREACH || errno == ENETDOWN ||
                    errno == EPERM || errno == EINTR) {
            // just log, do nothing
            err("recvfrom");
          } else {
            err("recvfrom");
            // TODO rebuild socket
            break;
          }
        }
        if (r == 0)
          continue;

        if (ctx->args->mode == SHADOWVPN_MODE_SERVER) {
          // if we are running a server, update server address from
          // recv_from
          memcpy(ctx->remote_addrp, &temp_remote_addr, temp_remote_addrlen);
          ctx->remote_addrlen = temp_remote_addrlen;
        }
        logf("Writing to tun %d bytes ...", r);
        if (-1 == tun_write(ctx->tun, ctx->udp_buf, r)) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // do nothing
          } else if (errno == EPERM || errno == EINTR || errno == EINVAL) {
            // just log, do nothing
            err("write to tun");
          } else {
            err("write to tun");
            break;
          }
        }
      }
    }
  }
  free(ctx->tun_buf);
  free(ctx->udp_buf);

  shell_down(ctx->args);

  close(ctx->tun);
  for (i = 0; i < ctx->nsock; i++) {
    close(ctx->socks[i]);
  }

  ctx->running = 0;

  return -1;
}

int vpn_stop(vpn_ctx_t *ctx) {
  logf("shutting down by user");
  if (!ctx->running) {
    errf("can not stop, not running");
    return -1;
  }
  ctx->running = 0;
  char buf = 0;
  if (-1 == write(ctx->control_pipe[1], &buf, 1)) {
    err("write");
    return -1;
  }
  return 0;
}

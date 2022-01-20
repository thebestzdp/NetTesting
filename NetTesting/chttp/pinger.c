//
//  pinger.c
//  ZHAgent2
//
//  Created by zhangdapeng on 2022/1/20.
//  Copyright © 2022 whlpsi. All rights reserved.
//

#include <stdio.h>


#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/types.h>
#include "pinger.h"

#define BOOL    int
#define FALSE   -1
#define TRUE    0

#define DATA_SIZE 32
#define MAX_RECV_SIZE 1024
#define HTTP_INVALID_SOCKET -1

/* #define PINGER_DEBUG 1 */
#if defined(PINGER_DEBUG)
#define dprintf(x,...) printf(x,##__VA_ARGS__)
#else
#define dprintf(x,...)
#endif

typedef struct _TAG_IP_HEADER
{
    u_int8_t    ip_head_verlen;
    u_int8_t    ip_tos;
    u_int16_t   ip_length;
    u_int16_t   ip_id;
    u_int16_t   ip_flags;
    u_int8_t    ip_ttl;
    u_int8_t    ip_protacol;
    u_int16_t   ip_checksum;
    u_int32_t   ip_source;
    u_int32_t   ip_destination;
} IP_HEADER;

typedef struct _TAG_IMCP_HEADER
{
    u_int8_t    icmp_type;
    u_int8_t    icmp_code;
    u_int16_t   check_sum;
    u_int16_t   icmp_id;
    u_int16_t   icmp_seq;
} ICMP_HEADER;

typedef struct _TAG_ICMP_PACKET
{
    ICMP_HEADER     icmp_header;
    struct timeval  icmp_time;
    u_int16_t       icmp_sum_flag;
    u_int8_t        imcp_data[DATA_SIZE];
} ICMP_PACKET;

struct simple_pinger_t
{
    const char * host;
    int timeout_ms;
    int         fd;  // socket
};


static u_int16_t generation_checksum(u_int16_t * buf, u_int32_t size)
{
    u_int64_t cksum = 0;
    while(size > 1)
    {
        cksum += *buf++;
        size -= sizeof(u_int16_t);
    }

    if(size)
    {
        cksum += *buf++;
    }

    cksum =  (cksum>>16) + (cksum & 0xffff);
    cksum += (cksum>>16);

    return (u_int16_t)(~cksum);
}

static double get_time_interval(struct timeval * start, struct timeval * end)
{
    double interval;
    struct timeval tp;

    tp.tv_sec = end->tv_sec - start->tv_sec;
    tp.tv_usec = end->tv_usec - start->tv_usec;
    if(tp.tv_usec < 0)
    {
        tp.tv_sec -= 1;
        tp.tv_usec += 1000000;
    }

    interval = tp.tv_sec * 1000 + tp.tv_usec * 0.001;
    return interval;
}

simple_pinger_t* pinger_new() {
    simple_pinger_t* pinger = (simple_pinger_t*)calloc(1, sizeof(simple_pinger_t));
    pinger->fd = HTTP_INVALID_SOCKET;
    return pinger;
}

void pinger_setParam(simple_pinger_t* pinger, const char * domain, int timeout_ms){
    if(!pinger)
        return;
    
    pinger->host = domain;
    pinger->timeout_ms = timeout_ms;
    pinger->fd = HTTP_INVALID_SOCKET;
}


void pinger_destroy(simple_pinger_t * pinger) {
    if(pinger == NULL) return;
    pinger->host = NULL;
    if(pinger->fd != HTTP_INVALID_SOCKET)
    {
        close(pinger->fd);
        pinger->fd = HTTP_INVALID_SOCKET;
    }

    free(pinger);
    pinger = NULL;
}
void pinger_cancel(simple_pinger_t * pinger) {
    if(pinger && pinger->fd != HTTP_INVALID_SOCKET)
    {
        close(pinger->fd);
        pinger->fd = HTTP_INVALID_SOCKET;
    }
}

int get_pinger_info(simple_pinger_t * pinger, ping_info * res_buffer) {
    int ret = -1;
    
    if(pinger == NULL)
        return ret;
    
//    int client_fd = pinger->fd;
    int size = 50 * MAX_RECV_SIZE;
    struct timeval timeout;
    ICMP_PACKET * icmp_packet = NULL;
    ICMP_HEADER * icmp_header = NULL;
    char * hostName = "-";
    const char * domain = pinger->host;
    in_addr_t dest_ip;
    struct sockaddr_in dest_socket_addr;
    
    if (res_buffer == NULL || domain == NULL)
    {
        return ret;
    }
    
    dest_ip = inet_addr(domain);
    if (dest_ip == INADDR_NONE)
    {
        struct hostent* p_hostent = gethostbyname(domain);
        if(p_hostent)
        {
            dest_ip = (*(in_addr_t*)p_hostent->h_addr);
            hostName = p_hostent->h_name;
        }
    }
    
    if (dest_ip == INADDR_NONE)
    {
        return ret;
    }

    pinger->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (pinger->fd == HTTP_INVALID_SOCKET)
    {
        dprintf("PING: socket error: %s!\n", strerror(errno));
        return ret;
    }

    int timeout_ms = pinger->timeout_ms;
    if(timeout_ms <= 0){
        timeout_ms = 3000;
    }
    timeout.tv_sec = timeout_ms/1000;
    timeout.tv_usec = ((timeout_ms % 1000) * 1000) * 1000;
    setsockopt(pinger->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if(setsockopt(pinger->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)))
    {
        dprintf("PING: setsocketopt SO_RCVTIMEO error: %s\n", strerror(errno));
        return ret;
    }

    if(setsockopt(pinger->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)))
    {
        dprintf("PING: setsockopt SO_SNDTIMEO error: %s\n", strerror(errno));
        return ret;
    }

    memset(dest_socket_addr.sin_zero, 0, sizeof(dest_socket_addr.sin_zero));
    dest_socket_addr.sin_family = AF_INET;
    dest_socket_addr.sin_addr.s_addr = dest_ip;
    dest_socket_addr.sin_port = htons(0);

    icmp_packet = (ICMP_PACKET *)malloc(sizeof(ICMP_PACKET));
    if (icmp_packet == NULL)
    {
        dprintf("PING: malloc error.\n");
        return ret;
    }

    memset(icmp_packet, 0, sizeof(ICMP_PACKET));

    icmp_header = &icmp_packet->icmp_header;
    icmp_header->icmp_type = 8;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_id = getpid();

    icmp_packet->icmp_sum_flag = generation_checksum((u_int16_t *)icmp_packet, sizeof(ICMP_PACKET));
    printf("NetTest:PING %s (%s).\n", hostName, inet_ntoa(*((struct in_addr*)&dest_ip)));
    if(domain[0] >= '0' && domain[0] <= '9')
    {
        // res_buffer->hostname_ = (char*)domain;
        strcpy(res_buffer->hostname_, (char*)domain);
    } else {
        strcpy(res_buffer->hostname_, hostName);
        // res_buffer->hostname_ = hostName;

    }
    res_buffer->ip_ = inet_ntoa(*((struct in_addr*)&dest_ip));
    
    do{
        long result = -1;
        icmp_header->icmp_seq = htons(0);
        icmp_header->check_sum = 0;
        gettimeofday(&icmp_packet->icmp_time, NULL);
        icmp_packet->icmp_sum_flag = 0;
        icmp_header->check_sum = generation_checksum((u_int16_t *) icmp_packet, sizeof(ICMP_PACKET));
        result = sendto(pinger->fd, icmp_packet, sizeof(ICMP_PACKET), 0, (struct sockaddr *)&dest_socket_addr,
                        sizeof(struct sockaddr_in));
        if (result == -1)
        {
            dprintf("PING: sendto: Network is unreachable\n");
            ret = -2;
            break;
        }
        
        struct sockaddr_in from;
        socklen_t from_packet_len;
        long read_length;
        char recv_buf[MAX_RECV_SIZE];
        struct timeval end;
        from_packet_len = sizeof(struct sockaddr_in);
        do
        {
            read_length = recvfrom(pinger->fd, recv_buf, MAX_RECV_SIZE, 0,
                                   (struct sockaddr*)&from, &from_packet_len);
            gettimeofday( &end, NULL );
            if(read_length != -1)
            {
                IP_HEADER * recv_ip_header = (IP_HEADER*)recv_buf;
                int ip_ttl = (int)recv_ip_header->ip_ttl;
                ICMP_PACKET * recv_icmp = (ICMP_PACKET *)(recv_buf +
                                                          (recv_ip_header->ip_head_verlen & 0x0F) * 4);
                
                if(recv_icmp->icmp_header.icmp_type != 0)
                {

                    dprintf("PING: error type %d received, error code %d \n", recv_icmp->icmp_header.icmp_type, recv_icmp->icmp_header.icmp_code);
                    continue;
                }
                if (recv_icmp->icmp_sum_flag != icmp_packet->icmp_sum_flag)
                {
                    dprintf("PING: check sum fail.\n");
                    continue;
                }
                if(read_length >= (0 + sizeof(ICMP_PACKET)))
                {
                    res_buffer->timeCost_ = get_time_interval(&recv_icmp->icmp_time, &end);

                    dprintf("PING: %ld bytes from (%s): icmp_seq=%d ttl=%d time=%.2f ms\n",
                              read_length, inet_ntoa(from.sin_addr), recv_icmp->icmp_header.icmp_seq / 256,
                              ip_ttl, get_time_interval(&recv_icmp->icmp_time, &end));
                    ret = 0;
                    break;
                }
            }
            else
            {
                if (errno != EAGAIN)
                {
                    dprintf("PING: receive data error: %s\n", strerror(errno));
                    res_buffer->timeCost_ = -1;
                }
                ret = -3;
                break;
            }
        }while(0);
    }while(0);
    res_buffer->lossRate_ = 0.0;
    if (icmp_packet != NULL)
    {
        free(icmp_packet);
        icmp_packet = NULL;
    }
    if (pinger->fd >= 0)
    {
        close(pinger->fd);
        pinger->fd = HTTP_INVALID_SOCKET;
    }

    return ret;
}

//
//  NetTrace.c
//  NetTesting
//
//  Created by zhangdapeng on 2022/1/12.
//

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

#include "NetTesting.h"

static struct timespec time_diff(struct timespec* begin, struct timespec* end)
{
    struct timespec tp;

    tp.tv_sec = end->tv_sec - begin->tv_sec;
    tp.tv_nsec = end->tv_nsec - begin->tv_nsec;

    if(tp.tv_nsec < 0)
    {
        tp.tv_sec -= 1;
        tp.tv_nsec += 1000000000;
    }

    return tp;
}


int trace_route(const char * domain) {
    int ret = -1;
    int client_fd = -1;
    int size = 50 * MAX_RECV_SIZE;
    struct timeval timeout;

    ICMP_PACKET * icmp_packet = NULL;
    ICMP_HEADER * icmp_header = NULL;

    in_addr_t dest_ip;
    struct sockaddr_in dest_socket_addr;
    
    dest_ip = inet_addr(domain);
    if (dest_ip == INADDR_NONE)
    {
        struct hostent* p_hostent = gethostbyname(domain);
        if(p_hostent)
        {
            dest_ip = (*(in_addr_t*)p_hostent->h_addr);
        }
    }
    
    if (dest_ip == INADDR_NONE)
    {
        return ret;
    }

    client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (client_fd == -1)
    {
        printf("TRACE: socket error: %s!\n", strerror(errno));
        return ret;
    }

    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if(setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)))
    {
        printf("TRACE: setsocketopt SO_RCVTIMEO error: %s\n", strerror(errno));
        return ret;
    }
    if(setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)))
    {
        printf("TRACE: setsockopt SO_SNDTIMEO error: %s\n", strerror(errno));
        return ret;
    }
    
    memset(dest_socket_addr.sin_zero, 0, sizeof(dest_socket_addr.sin_zero));
    dest_socket_addr.sin_family = AF_INET;
    dest_socket_addr.sin_addr.s_addr = dest_ip;
    dest_socket_addr.sin_port = htons(0);

    int ttl = 1;
    setsockopt(client_fd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));

    unsigned char buffer[1024];

    int maxfds = client_fd + 1;
    fd_set rset;
    int try_cnt = 0;
    struct sockaddr_in from;
    socklen_t from_len;
    struct timespec time_before;

    while(ttl <= 20)
    {
        ssize_t len;

        FD_ZERO(&rset);
        FD_SET(client_fd, &rset);
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        from_len = sizeof(from);
        
        icmp_packet = (ICMP_PACKET *)malloc(sizeof(ICMP_PACKET));
        if (icmp_packet == NULL)
        {
            printf("TRACE: malloc error.\n");
            return ret;
        }

        memset(icmp_packet, 0, sizeof(ICMP_PACKET));

        icmp_header = &icmp_packet->icmp_header;
        icmp_header->icmp_type = 8;
        icmp_header->icmp_code = 0;
        icmp_header->icmp_id = getpid();
        clock_gettime(CLOCK_REALTIME, &time_before);
        icmp_packet->icmp_sum_flag = generation_checksum((u_int16_t *)icmp_packet, sizeof(ICMP_PACKET));
        ssize_t nbs = sendto(client_fd, icmp_packet, sizeof(ICMP_PACKET), 0, (struct sockaddr *)&dest_socket_addr,
                        sizeof(struct sockaddr_in));
        if(nbs < 0)
        {
            printf("TRACE: sendto : %s\n", strerror(errno));
        }

        int res = select(maxfds, &rset, NULL, NULL, &timeout);
        if(res < 0)
        {
            printf("TRACE: select error: %s\n", strerror(errno));
            break;
        }

        if(res == 0)
        {
            if(try_cnt == 4)
            {
                printf("TRACE: ttl :%d from (%s):\n",
                          ttl,"* * * ");
                ttl++;
                try_cnt = 0;
                setsockopt(client_fd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                continue;
            }

            try_cnt++;
            continue;
        }
        else
        {

            if((len = recvfrom(client_fd, buffer, MAX_RECV_SIZE, 0,
                               (struct sockaddr*)&from, &from_len)) <= 0)
            {
                printf("TRACE: recvfrom error: %s\n", strerror(errno));
                    break;
            }


            if(from.sin_addr.s_addr == dest_socket_addr.sin_addr.s_addr)
            {
                struct timespec tnow;
                clock_gettime(CLOCK_REALTIME, &tnow);

                struct timespec diff;
                diff = time_diff(&time_before, &tnow);
                double timems = diff.tv_sec * 1000 + (diff.tv_nsec / 1000000.0);

                
                IP_HEADER * recv_ip_header = (IP_HEADER*)buffer;
                ICMP_PACKET * recv_icmp = (ICMP_PACKET *)(buffer +
                                                          (recv_ip_header->ip_head_verlen & 0x0F) * 4);
                
                
                
                printf("TRACE: ttl: %d from (%s): time=%.3f ms\n",
                           ttl ,inet_ntoa(from.sin_addr), timems);
                
                printf("TRACE: traceroute completed\n");
                break;
            }

            if(try_cnt < 4)
            {
                struct timespec tnow;
                clock_gettime(CLOCK_REALTIME, &tnow);

                struct timespec diff;
                diff = time_diff(&time_before, &tnow);
                double timems = diff.tv_sec * 1000 + (diff.tv_nsec / 1000000.0);

                
                IP_HEADER * recv_ip_header = (IP_HEADER*)buffer;
                ICMP_PACKET * recv_icmp = (ICMP_PACKET *)(buffer +
                                                          (recv_ip_header->ip_head_verlen & 0x0F) * 4);
                
                printf("TRACE: ttl: %d from (%s): time=%.3f ms\n",
                           ttl ,inet_ntoa(from.sin_addr), timems);
                
                ttl++;
                try_cnt = 0;
                setsockopt(client_fd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                continue;
            }
                else
            {
                printf("TRACE: ttl :%d from (%s):\n",
                          ttl,"* * * ");
                ttl++;
                try_cnt = 0;
                setsockopt(client_fd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                continue;
            }

//            try_cnt++;
        }
    }
    
    return 0;
}


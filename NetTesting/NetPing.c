//
//  NetPing.c
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

u_int16_t generation_checksum(u_int16_t * buf, u_int32_t size)
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

double get_time_interval(struct timeval * start, struct timeval * end)
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

static void * send_imcp(void *arg)
{
    u_int8_t *flag  = NULL;
    int times       = -1;
    int fd          = -1;
    struct sockaddr_in * dest_socket_addr;
    ICMP_HEADER *icmp_header = NULL;
    ICMP_PACKET *icmp_packet = NULL;

    THREAD_DATA *thread_data = (THREAD_DATA *)arg;
    if (thread_data == NULL)
    {
        return NULL;
    }

    dest_socket_addr = thread_data->sockaddr;
    if (dest_socket_addr == NULL)
    {
        return NULL;
    }

    flag  = &thread_data->send_flag;
    if (flag == NULL)
    {
        return NULL;
    }

    times = thread_data->times;
    fd = thread_data->fd;
    if (fd <= 0)
    {
        return NULL;
    }

    icmp_packet = thread_data->icmp_packet;
    if (icmp_packet == NULL)
    {
        return NULL;
    }

    icmp_header = &(icmp_packet->icmp_header);
    if (icmp_header == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < thread_data->times; i++)
    {
        long result = -1;
        icmp_header->icmp_seq = htons(i);
        icmp_header->check_sum = 0;

        // printf("send packet. %s\n", inet_ntoa(*((struct in_addr*)&(dest_socket_addr->sin_addr.s_addr))));
        gettimeofday(&icmp_packet->icmp_time, NULL);
        icmp_packet->icmp_sum_flag = 0;
        icmp_header->check_sum = generation_checksum((u_int16_t *) icmp_packet, sizeof(ICMP_PACKET));
        // printf("send sum: %x\n", icmp_header->check_sum);
        result = sendto(fd, icmp_packet, sizeof(ICMP_PACKET), 0, (struct sockaddr *)dest_socket_addr,
                        sizeof(struct sockaddr_in));
        if (result == -1)
        {
            printf("PING: sendto: Network is unreachable\n");
            continue;
        }

        sleep(1);
    }

    *flag = 0;
    return NULL;
}

static void * recv_imcp(void *arg)
{
    u_int8_t *flag  = NULL;
    int times       = -1;
    int fd          = -1;
    ICMP_HEADER *icmp_header = NULL;
    ICMP_PACKET *icmp_packet = NULL;

    THREAD_DATA *thread_data = (THREAD_DATA *)arg;
    if (thread_data == NULL)
    {
        return NULL;
    }

    flag  = &thread_data->send_flag;
    if (flag == NULL)
    {
        return NULL;
    }

    times = thread_data->times;
    fd = thread_data->fd;
    if (fd <= 0)
    {
        return NULL;
    }

    icmp_packet = thread_data->icmp_packet;
    if (icmp_packet == NULL)
    {
        return NULL;
    }

    icmp_header = &(icmp_packet->icmp_header);
    if (icmp_header == NULL)
    {
        return NULL;
    }

    struct sockaddr_in from;
    socklen_t from_packet_len;
    long read_length;
    char recv_buf[MAX_RECV_SIZE];
    struct timeval end;

    from_packet_len = sizeof(struct sockaddr_in);
    for (int index = 0; index < times && *flag == 1;)
    {
        read_length = recvfrom(fd, recv_buf, MAX_RECV_SIZE, 0,
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

                printf("PING: error type %d received, error code %d \n", recv_icmp->icmp_header.icmp_type, recv_icmp->icmp_header.icmp_code);
                continue;
            }

            if (recv_icmp->icmp_sum_flag != icmp_packet->icmp_sum_flag)
            {
                printf("PING: check sum fail.\n");
                continue;
            }

            if(read_length >= (0 + sizeof(ICMP_PACKET)))
            {
                index++;
                snprintf(thread_data->buffer, thread_data->buffer_len, "%s%ld bytes from (%s): icmp_seq=%d time=%.2f ms\n",
                 thread_data->buffer, read_length, inet_ntoa(from.sin_addr),
                 recv_icmp->icmp_header.icmp_seq / 256, get_time_interval(&recv_icmp->icmp_time, &end));

                printf("PING: %ld bytes from (%s): icmp_seq=%d ttl=%d time=%.2f ms\n",
                          read_length, inet_ntoa(from.sin_addr), recv_icmp->icmp_header.icmp_seq / 256,
                          ip_ttl, get_time_interval(&recv_icmp->icmp_time, &end));
            }
        }
        else
        {
            if (errno != EAGAIN)
            {
                printf("PING: receive data error: %s\n", strerror(errno));
                snprintf(thread_data->buffer, thread_data->buffer_len, "receive data error: %s\n", strerror(errno));
            }
        }
    }

    return NULL;
}


int ping_result(const char * domain, u_int32_t times, char * res_buffer, int buffer_len)
{
    int ret = -1;
    int client_fd = -1;
    int size = 50 * MAX_RECV_SIZE;
    struct timeval timeout;

    ICMP_PACKET * icmp_packet = NULL;
    ICMP_HEADER * icmp_header = NULL;
    char * hostName = NULL;
    in_addr_t dest_ip;
    struct sockaddr_in dest_socket_addr;

    pthread_t send_pid;
    pthread_t recv_pid;

    THREAD_DATA thread_data;

    if (res_buffer == NULL || domain == NULL || buffer_len == 0)
    {
        printf("PING: res_buffer: %s, domain: %s, buffer_len: %d\n", res_buffer, domain, buffer_len);
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

    client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (client_fd == -1)
    {
        printf("PING: socket error: %s!\n", strerror(errno));
        return ret;
    }

    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if(setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)))
    {
        printf("PING: setsocketopt SO_RCVTIMEO error: %s\n", strerror(errno));
        return ret;
    }

    if(setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)))
    {
        printf("PING: setsockopt SO_SNDTIMEO error: %s\n", strerror(errno));
        return ret;
    }

    memset(dest_socket_addr.sin_zero, 0, sizeof(dest_socket_addr.sin_zero));
    dest_socket_addr.sin_family = AF_INET;
    dest_socket_addr.sin_addr.s_addr = dest_ip;
    dest_socket_addr.sin_port = htons(0);

    icmp_packet = (ICMP_PACKET *)malloc(sizeof(ICMP_PACKET));
    if (icmp_packet == NULL)
    {
        printf("PING: malloc error.\n");
        return ret;
    }

    memset(icmp_packet, 0, sizeof(ICMP_PACKET));

    icmp_header = &icmp_packet->icmp_header;
    icmp_header->icmp_type = 8;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_id = getpid();

    icmp_packet->icmp_sum_flag = generation_checksum((u_int16_t *)icmp_packet, sizeof(ICMP_PACKET));
    printf("PING %s (%s).\n", hostName, inet_ntoa(*((struct in_addr*)&dest_ip)));
    snprintf(res_buffer, buffer_len, "PING %s (%s).\n", hostName, inet_ntoa(*((struct in_addr*)&dest_ip)));

    thread_data.send_flag   = 1;
    thread_data.sockaddr    = &dest_socket_addr;
    thread_data.fd          = client_fd;
    thread_data.buffer      = res_buffer;
    thread_data.times       = times;
    thread_data.icmp_packet = icmp_packet;
    thread_data.buffer_len  = buffer_len;

    ret = pthread_create(&send_pid, NULL, send_imcp, (void *)&thread_data);
    if (ret < 0)
    {
        printf("PING: pthread create error: %s\n", strerror(errno));
        goto FAIL_EXIT;
    }

    ret = pthread_create(&recv_pid, NULL, recv_imcp, (void *)&thread_data);
    if (ret < 0)
    {
        printf("PING: pthread create error: %s\n", strerror(errno));
        pthread_detach(send_pid);
        goto FAIL_EXIT;
    }

    pthread_join(send_pid, NULL);
    pthread_join(recv_pid, NULL);

FAIL_EXIT:
    if (icmp_packet != NULL)
    {
        free(icmp_packet);
        icmp_packet = NULL;
    }

    if (client_fd >= 0)
    {
        close(client_fd);
        client_fd = -1;
    }
    
    return ret;
}

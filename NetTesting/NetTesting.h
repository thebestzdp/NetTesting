//
//  NetTesting.h
//  NetTesting
//
//  Created by zhangdapeng on 2022/1/12.
//

#ifndef NetTesting_h
#define NetTesting_h

#ifdef __cplusplus
extern "C"{
#endif

#include <stdio.h>

#define BOOL    int
#define FALSE   -1
#define TRUE    0

#define DATA_SIZE 32
#define MAX_RECV_SIZE 1024

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

typedef struct _TAG_THREAD_DATA
{
    int         fd;
    u_int32_t   times;
    ICMP_PACKET * icmp_packet;
    char        * buffer;
    u_int32_t   buffer_len;
    struct sockaddr_in * sockaddr;
    u_int8_t    send_flag;
} THREAD_DATA;

u_int16_t generation_checksum(u_int16_t * buf, u_int32_t size);
double get_time_interval(struct timeval * start, struct timeval * end);


// ping
int ping_result(const char * domain, u_int32_t times, char * res_buffer, int buffer_len);

// trace
int trace_route(const char * domain);

#ifdef __cplusplus
}
#endif

int curl_connect_http(const char * url);

#endif /* NetTesting_h */

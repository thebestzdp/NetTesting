//
//  pinger.h
//  ZHAgent2
//
//  Created by zhangdapeng on 2022/1/20.
//  Copyright © 2022 whlpsi. All rights reserved.
//

#ifndef pinger_h
#define pinger_h

#ifdef __cplusplus
extern "C"{
#endif

typedef struct ping_info
{
    char hostname_[512];
    char * ip_;
    int timeCost_;
    float lossRate_;
}ping_info;


struct simple_pinger_t;
typedef struct simple_pinger_t simple_pinger_t;

simple_pinger_t* pinger_new(void);
void pinger_setParam(simple_pinger_t* pinger, const char * domain, int timeout_ms);
void pinger_destroy(simple_pinger_t * pinger);
void pinger_cancel(simple_pinger_t * pinger);
int get_pinger_info(simple_pinger_t * pinger, ping_info * res_buffer);


#ifdef __cplusplus
}
#endif

#endif /* pinger_h */

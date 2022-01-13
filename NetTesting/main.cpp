//
//  main.cpp
//  NetTesting
//
//  Created by zhangdapeng on 2022/1/12.
//

#include <iostream>
#include "NetTesting.h"

#define PING_RES_BUFFER_LEN 1024

int main(int argc, const char * argv[]) {
    
    char res_buffer[PING_RES_BUFFER_LEN];
    char * domain = "www.google.com";
    int res = ping_result(domain, 2, res_buffer, PING_RES_BUFFER_LEN);
    if(!res)
        printf("PINGER: %s \n",res_buffer);
    
    curl_connect_http("https://www.google.com");
    trace_route(domain);
    
    return 0;
}

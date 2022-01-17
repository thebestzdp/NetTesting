//
//  main.cpp
//  NetTesting
//
//  Created by zhangdapeng on 2022/1/12.
//

#include <iostream>
#include "NetTesting.h"
#include "http.h"

#define PING_RES_BUFFER_LEN 1024
int main(int argc, const char * argv[]) {
    
    char res_buffer[PING_RES_BUFFER_LEN];
    char * domain = "www.google.com";
    int res = ping_result(domain, 2, res_buffer, PING_RES_BUFFER_LEN);
    if(!res)
        printf("PINGER: %s \n",res_buffer);
    ///
    ft_http_client_t* http = 0;
    ft_http_init();
    http = ft_http_new();
    const char* body = 0;
    body = ft_http_sync_request(http, "https://www.google.com", M_GET);
    printf("ft_http get:%s\n", body);
    if (http) {
        ft_http_destroy(http);
    }
    ft_http_deinit();
    ///
    
    curl_connect_http(domain);
    trace_route(domain);
    
    return 0;
}

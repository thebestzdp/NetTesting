//
//  CurlConnection.cpp
//  NetTesting
//
//  Created by zhangdapeng on 2022/1/12.
//

#include <stdio.h>
#include "curl/curl.h"


int curl_connect_http(const char * url) {
    CURL *curl;
    CURLcode res = (CURLcode)0;
    if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        return -1;
    }
    curl = curl_easy_init();
    if(curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // 支持重定向
        curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);   // 开启 fast open
        res = curl_easy_perform(curl);
        if(CURLE_OK == res){
            long retcode = 0;
            char *ipAddress={0};
            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE , &retcode);
            res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP,&ipAddress);
            double totalTime = 0.0;
            res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME,&totalTime);
            if(res == CURLE_OK){
                printf("CURL: t:%.3f \n",totalTime);
            }
            printf("CURL: check the network connection url %s, res: %d, status: %ld\n",url,res,retcode);
        }
        else {
            printf("CURL: Network unConnection res %d \n",res);
        }
        curl_easy_cleanup(curl);
    } else {
        printf("CURL: Curl Init Error!");
    }
    
    return  res;
    
    
    
}

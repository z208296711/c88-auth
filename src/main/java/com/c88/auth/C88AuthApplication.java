package com.c88.auth;

import com.c88.admin.api.OAuthClientFeignClient;
import com.c88.admin.api.UserFeignClient;
import com.c88.affiliate.api.feign.AffiliateFeignClient;
import com.c88.member.api.MemberFeignClient;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.cloud.openfeign.EnableFeignClients;

@EnableHystrix
@EnableDiscoveryClient
@EnableFeignClients(basePackageClasses = {
        UserFeignClient.class,
        OAuthClientFeignClient.class,
        MemberFeignClient.class,
        AffiliateFeignClient.class
})
@SpringBootApplication
public class C88AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(C88AuthApplication.class, args);
    }

}

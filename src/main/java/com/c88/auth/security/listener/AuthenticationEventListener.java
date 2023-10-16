package com.c88.auth.security.listener;

import cn.hutool.core.bean.BeanUtil;
import com.c88.admin.api.UserFeignClient;
import com.c88.admin.dto.UserLoginDto;
import com.c88.amqp.AuthToken;
import com.c88.amqp.EventType;
import com.c88.amqp.producer.MessageProducer;
import com.c88.auth.common.uitl.GeoIPUtils;
import com.c88.auth.security.core.userdetails.member.MemberUserDetails;
import com.c88.auth.security.core.userdetails.user.SysUserDetails;
import com.c88.common.core.enums.AuthenticationIdentityEnum;
import com.maxmind.geoip2.model.CityResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationEventListener {

    private final GeoIPUtils geoIPUtils;

    private final UserFeignClient userFeignClient;

    private final MessageProducer messageProducer;

    @EventListener
    public void doLoginEvent(AuthenticationSuccessEvent event) {
        if (event.getAuthentication().getPrincipal() instanceof SysUserDetails) {

            SysUserDetails sysUserDetails = (SysUserDetails) event.getAuthentication().getPrincipal();
            UserLoginDto userLoginDto = new UserLoginDto();
            LinkedHashMap<String, String> detailMap = (LinkedHashMap<String, String>) event.getAuthentication().getDetails();
            userLoginDto.setUserId(sysUserDetails.getUserId());
            userLoginDto.setBrowser(detailMap.get("browser"));
            userLoginDto.setOs(detailMap.get("os"));
            //判斷找不到時就不塞入城市及國家代碼
            String clientIP = detailMap.get("clientIP");
            try {
                CityResponse geoResponse = geoIPUtils.getGeoResponseByIP(clientIP);
                String province = geoResponse.getCountry().getIsoCode();
                String city = geoResponse.getCity().getName();
                userLoginDto.setArea(province);
                userLoginDto.setCity(city);
                log.info("login user:{},province:{} ,city:{}", event.getAuthentication().getName(), province, city);
            } catch (Exception e) {
                log.info("get city fail");
            }
            userLoginDto.setUsername(event.getAuthentication().getName());
            userLoginDto.setIp(clientIP);
            userFeignClient.addUserLoginRecord(userLoginDto);
        } else if (event.getAuthentication().getPrincipal() instanceof MemberUserDetails) {
            AuthToken token = BeanUtil.copyProperties(event.getAuthentication().getPrincipal(), AuthToken.class);
            LinkedHashMap<String, String> detailMap = (LinkedHashMap<String, String>) event.getAuthentication().getDetails();
            String clientIP = detailMap.get("clientIP");
            Map<String,String> cityMap = parseCity(clientIP);
            String province = Optional.ofNullable(cityMap.get("province")).orElse("");
            String city = Optional.ofNullable(cityMap.get("city")).orElse("");
            token.setArea(province+"/"+city);
            token.setIp(clientIP);
            token.setDeviceCode(detailMap.get("deviceCode"));
            token.setDevice(detailMap.get("device"));
            token.setLoginDomain(detailMap.get("loginDomain"));
            messageProducer.sendMessage(EventType.LOGIN_SUCCESS, token);
        }
    }

    @EventListener
    public void failureEvent(AuthenticationFailureBadCredentialsEvent event) {
        AuthToken token = BeanUtil.copyProperties(event.getAuthentication(), AuthToken.class);
        token.setUserName(String.valueOf(((Map) event.getAuthentication().getDetails()).get(AuthenticationIdentityEnum.USERNAME.getValue())));
        messageProducer.sendMessage(EventType.LOGIN_ERROR, token);
    }

    private Map<String,String> parseCity(String clientIP){
        Map<String,String> retMap = new HashMap<>();
        try {
            CityResponse geoResponse = geoIPUtils.getGeoResponseByIP(clientIP);
            String province = geoResponse.getCountry().getIsoCode();
            String city = geoResponse.getCity().getName();
            retMap.put("province",province);
            retMap.put("city",city);
        } catch (Exception e) {
            log.info("parse city fail");
        }
        return retMap;
    }

}

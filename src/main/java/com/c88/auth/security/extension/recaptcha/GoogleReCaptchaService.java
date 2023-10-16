package com.c88.auth.security.extension.recaptcha;

import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Data
public class GoogleReCaptchaService {

    private String validUrl;

    private String secret;

    private RestTemplate restTemplate;

    public void verifyGoogleCaptcha(String host, String code) {
        Assert.isTrue(StrUtil.isNotBlank(code), "验证码不能为空");
        boolean isGooglePass = false;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("secret", secret);
        map.add("response", code);
        map.add("remoteip", host);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        //todo  暫時移除 google ReCaptcha 驗證

        // log.info("GoogleReCaptchaService validUrl:{}, param:{}", this.validUrl, request.getBody());
        // ResponseEntity<String> response = restTemplate.postForEntity(validUrl, request, String.class);
        // HttpStatus statusCode = response.getStatusCode();
        // if (statusCode == HttpStatus.OK) {
        //     JSONObject json = JSON.parseObject(response.getBody());
        //     boolean success = json.getBoolean("success");
        //     boolean scoreValid = true;
        //     //for V3
        //     if (json.containsKey("score")) {
        //         scoreValid = json.getDouble("score") >= 0.9D;
        //     }
        //     log.info("success:{}, scoreValid:{}", success, scoreValid);
        //     isGooglePass = success && scoreValid;
        // }
        // Assert.isTrue(isGooglePass, "GOOGLE ROBOT NOT PASS");
    }
}

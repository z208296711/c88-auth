package com.c88.auth.config;

import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaService;
import feign.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;


@Configuration
public class GoogleRecaptchaConfig {

    @Value("${recaptcha.url}")
    private String validUrl;

    @Value("${recaptcha.secret}")
    private String secret;

    @Bean
    public GoogleReCaptchaService googleReCaptchaService() {
        GoogleReCaptchaService service = new GoogleReCaptchaService();
        service.setSecret(secret);
        service.setValidUrl(validUrl);
        service.setRestTemplate(new RestTemplate());
        return service;
    }

    @Bean
    Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }

}

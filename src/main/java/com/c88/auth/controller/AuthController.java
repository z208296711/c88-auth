package com.c88.auth.controller;

import cn.hutool.extra.servlet.ServletUtil;
import cn.hutool.http.useragent.UserAgent;
import cn.hutool.http.useragent.UserAgentUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaService;
import com.c88.common.core.constant.RedisConstants;
import com.c88.common.core.constant.SecurityConstants;
import com.c88.common.core.result.Result;
import com.c88.common.web.util.JwtUtils;
import com.c88.common.web.util.RequestUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.swagger.annotations.ApiOperation;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.c88.common.core.constant.RedisConstants.ONLINE_MEMBER;
import static com.c88.common.core.constant.SecurityConstants.MEMBER_ID;
import static com.c88.common.redis.utils.RedisUtils.buildKey;

@Tag(name = "认证中心")
@RestController
@RequestMapping("/oauth")
@AllArgsConstructor
@Slf4j
public class AuthController {

    private TokenEndpoint tokenEndpoint;
    private TokenStore tokenStore;
    private RedisTemplate<String,Object> redisTemplate;
    private KeyPair keyPair;
    private GoogleReCaptchaService googleReCaptchaService;


    @Operation(summary = "OAuth2认证", description = "登录入口")
    @PostMapping("/token")
    public Object postAccessToken(
            Principal principal,
            HttpServletRequest request,
            @RequestHeader("host") String host,
            @RequestHeader("user-agent") String userAgentStr,
            @RequestParam Map<String, String> parameters
    ) throws HttpRequestMethodNotSupportedException {


        String clientId = RequestUtils.getOAuth2ClientId();
        log.info("OAuth认证授权 客户端ID:{}，请求参数：{}", clientId, JSONUtil.toJsonStr(parameters));

        //處理 相關額外紀錄 browser & os
        UserAgent ua = UserAgentUtil.parse(request.getHeader("user-agent"));
        if (ua != null) {
            parameters.put("browser", ua.getBrowser().toString());
            parameters.put("os", ua.getOs().toString());
        }
        String clientIP = ServletUtil.getClientIP(request);
        parameters.put("clientIP", clientIP);
        parameters.put("host", host);
        OAuth2AccessToken accessToken = tokenEndpoint.postAccessToken(principal, parameters).getBody();
        return Result.success(accessToken);
    }

    @ApiOperation(value = "注销")
    @DeleteMapping("/logout")
    public Result<String> logout() {
        JSONObject payload = JwtUtils.getJwtPayload();
        Long memberId = payload.getLong(MEMBER_ID);
        String jti = payload.getStr(SecurityConstants.JWT_JTI); // JWT唯一标识
        Long expireTime = payload.getLong(SecurityConstants.JWT_EXP); // JWT过期时间戳(单位：秒)
        if (expireTime != null) {
            long currentTime = System.currentTimeMillis() / 1000;// 当前时间（单位：秒）
            if (expireTime > currentTime) { // token未过期，添加至缓存作为黑名单限制访问，缓存时间为token过期剩余时间
                redisTemplate.opsForValue().set(SecurityConstants.TOKEN_BLACKLIST_PREFIX + jti, null, (expireTime - currentTime), TimeUnit.SECONDS);
            }
        } else { // token 永不过期则永久加入黑名单
            redisTemplate.opsForValue().set(SecurityConstants.TOKEN_BLACKLIST_PREFIX + jti, null);
        }
        if (memberId != null) {// 會員登出，移除在線記錄
            redisTemplate.delete(buildKey(ONLINE_MEMBER, String.valueOf(memberId)));
        }
        return Result.success("注销成功");
    }

    @ApiOperation(value = "获取公钥")
    @GetMapping("/public-key")
    public Map<String, Object> getPublicKey() {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKey key = new RSAKey.Builder(publicKey).build();
        return new JWKSet(key).toJSONObject();
    }

    @GetMapping("/googleRecaptcha/{userName}")
    public boolean googleRecaptcha(@PathVariable("userName") String userName, @RequestHeader("token") String token) {
        googleReCaptchaService.verifyGoogleCaptcha(null, token);
        String key = buildKey(RedisConstants.GOOGLE_RECAPTCHA, userName);
        redisTemplate.opsForValue().set(key, token);
        return redisTemplate.expire(key, Duration.ofMinutes(1));
    }


    @DeleteMapping("/clean")
    public boolean cleanToken(@RequestParam(value = "clientId") String clientId,
                               @RequestParam(value = "username", required = false) String username) {
        log.info("oauth token clean-> clientId:{}, username:{}", clientId, username);
        if (StringUtils.isNotEmpty(username)) {
            Collection<OAuth2AccessToken> list = tokenStore.findTokensByClientIdAndUserName(clientId, username);
            list.forEach(oAuth2AccessToken -> tokenStore.removeAccessToken(oAuth2AccessToken));
        } else {
            Collection<OAuth2AccessToken> list = tokenStore.findTokensByClientId(clientId);
            list.forEach(oAuth2AccessToken -> tokenStore.removeAccessToken(oAuth2AccessToken));
        }
        return true;
    }


}

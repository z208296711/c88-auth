package com.c88.auth.security.extension.affiliate;

import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaService;
import com.c88.common.core.constant.RedisConstants;
import com.c88.common.redis.utils.RedisUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import static com.c88.auth.constants.KeyConstants.NOT_VALID_IP;

/**
 * 會員授權者
 */
public class AffiliateTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "affiliate";
    private final AuthenticationManager authenticationManager;
    private GoogleReCaptchaService googleReCaptchaService;
    private RedisTemplate<String, Object> redisTemplate;

    public AffiliateTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
                                 OAuth2RequestFactory requestFactory, AuthenticationManager authenticationManager,
                                 GoogleReCaptchaService googleReCaptchaService,
                                 RedisTemplate<String, Object> redisTemplate) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.authenticationManager = authenticationManager;
        this.googleReCaptchaService = googleReCaptchaService;
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());

        String userName = parameters.get("username"); // 會員帳號
        String password = parameters.get("password"); // 密碼
        String host = parameters.get("host");
        String clientIp = parameters.get("clientIP");
        String token = parameters.get("token");

        Object redisToken = redisTemplate.opsForValue().get(RedisUtils.buildKey(RedisConstants.GOOGLE_RECAPTCHA, userName));

        // local 測試不用 Google recaptcha
        if (!NOT_VALID_IP.contains(clientIp) &&
                (redisToken == null || !Objects.equals(token, redisToken))) {// 會員註冊時，會先進行Google recaptcha，而 recaptcha token 只能使用一次，透過 redis 記錄合法的 recaptcha token, 這邊就不用進行Google驗證
            googleReCaptchaService.verifyGoogleCaptcha(host, token);
        }

        parameters.remove("password");
        parameters.remove("host");
        parameters.remove("token");

        Authentication userAuth = new AffiliateToken(userName, password);
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);

        try {
            userAuth = this.authenticationManager.authenticate(userAuth);
        } catch (DisabledException var8) {
            throw new DisabledException(var8.getMessage());
        } catch (AccountStatusException var8) {
            throw new InvalidGrantException(var8.getMessage());
        } catch (BadCredentialsException var9) {
            throw new InvalidGrantException(var9.getMessage());
        }

        if (userAuth != null && userAuth.isAuthenticated()) {
            OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);
            return new OAuth2Authentication(storedOAuth2Request, userAuth);
        } else {
            throw new InvalidGrantException("Could not authenticate user: " + userName);
        }
    }
}

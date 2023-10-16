package com.c88.auth.security.extension.mobile;

import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaService;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.c88.auth.constants.KeyConstants.NOT_VALID_IP;

/**
 * 手機驗證碼授權者
 */
public class SmsCodeTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "member_sms";
    private final AuthenticationManager authenticationManager;
    private GoogleReCaptchaService googleReCaptchaService;

    public SmsCodeTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
                               OAuth2RequestFactory requestFactory, AuthenticationManager authenticationManager,
                               GoogleReCaptchaService googleReCaptchaService
    ) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.authenticationManager = authenticationManager;
        this.googleReCaptchaService = googleReCaptchaService;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap(tokenRequest.getRequestParameters());

        String mobile = parameters.get("mobile"); // 手机号
        String code = parameters.get("code"); // 短信验证码
        String sessionId = parameters.get("sessionId");
        String host = parameters.get("host");
        String clientIp = parameters.get("clientIP");
        String token = parameters.get("token");

        // local 測試不用 Google recaptcha
        if (!NOT_VALID_IP.contains(clientIp)) {
            googleReCaptchaService.verifyGoogleCaptcha(host, token);
        }

        parameters.remove("code");
        parameters.remove("host");
        parameters.remove("token");

        Authentication userAuth = new CodeAuthenticationToken(mobile, code, sessionId, true);
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);

        try {
            userAuth = this.authenticationManager.authenticate(userAuth);
        } catch (AccountStatusException var8) {
            throw new InvalidGrantException(var8.getMessage());
        } catch (BadCredentialsException var9) {
            throw new InvalidGrantException(var9.getMessage());
        }

        if (userAuth != null && userAuth.isAuthenticated()) {
            OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);
            return new OAuth2Authentication(storedOAuth2Request, userAuth);
        } else {
            throw new InvalidGrantException("Could not authenticate user: " + mobile);
        }
    }
}

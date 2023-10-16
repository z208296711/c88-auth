package com.c88.auth.security.extension.email;

import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaService;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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

import static com.c88.auth.constants.KeyConstants.NOT_VALID_IP;

/**
 * 電子郵件驗證碼授權者
 */
public class EmailCodeTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "member_email";
    private final AuthenticationManager authenticationManager;
    private GoogleReCaptchaService googleReCaptchaService;

    public EmailCodeTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
                                 OAuth2RequestFactory requestFactory, AuthenticationManager authenticationManager,
                                 GoogleReCaptchaService googleReCaptchaService
    ) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.authenticationManager = authenticationManager;
        this.googleReCaptchaService = googleReCaptchaService;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());

        String email = parameters.get("email"); // 電子郵件
        String code = parameters.get("code"); // 驗證碼
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

        // email 與 sms 可以共用 AuthenticationProvider，所以也使用 SmsCodeAuthenticationToken
        Authentication userAuth = new EmailCodeAuthenticationToken(email, code, sessionId, false);
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
            throw new InvalidGrantException("Could not authenticate user: " + email);
        }
    }
}

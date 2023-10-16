package com.c88.auth.security.extension.affiliate;

import com.c88.affiliate.api.feign.AffiliateFeignClient;
import com.c88.common.core.result.ResultCode;
import com.c88.common.redis.utils.RedisUtils;
import com.c88.common.web.exception.BizException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Data
public class AffiliateDaoAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;
    private AffiliateFeignClient memberFeignClient;
    private RedisUtils redisUtils;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AffiliateToken authenticationToken = (AffiliateToken) authentication;
        String username = (String) authenticationToken.getPrincipal();
        String presentedPassword = (String) authenticationToken.getCredentials();
        // 密碼比对
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!this.getPasswordEncoder().matches(presentedPassword, userDetails.getPassword())) {
            log.debug("Failed to authenticate since password does not match stored value is " + userDetails.getPassword());
            /**
             * 在這直接丟出 BizException 來中斷後續的 provider.authenticate,
             * 參考：{@link org.springframework.security.authentication.ProviderManager#authenticate(org.springframework.security.core.Authentication)}
             */
            throw new BizException(ResultCode.USERNAME_OR_PASSWORD_ERROR);
        }


        AffiliateToken result = new AffiliateToken(userDetails, authentication.getCredentials());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AffiliateToken.class.isAssignableFrom(authentication);
    }

}

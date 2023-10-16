package com.c88.auth.security.extension.member;

import com.c88.common.core.result.ResultCode;
import com.c88.common.web.exception.BizException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class MemberDaoAuthenticationProvider extends DaoAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            this.logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        String presentedPassword = authentication.getCredentials().toString();
        if (!this.getPasswordEncoder().matches(presentedPassword, userDetails.getPassword())) {
            this.logger.debug("Failed to authenticate since password does not match stored value is " + userDetails.getPassword());
            /**
             * 在這直接丟出 BizException 來中斷後續的 provider.authenticate,
             * 參考：{@link org.springframework.security.authentication.ProviderManager#authenticate(org.springframework.security.core.Authentication)}
             */
            throw new BizException(ResultCode.USERNAME_OR_PASSWORD_ERROR);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MemberToken.class.isAssignableFrom(authentication);
    }

}

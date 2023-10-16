package com.c88.auth.security.extension.mobile;

import cn.hutool.core.util.StrUtil;
import com.c88.auth.security.core.userdetails.member.MemberUserDetailsServiceImpl;
import com.c88.common.redis.utils.RedisUtils;
import com.c88.common.web.exception.BizException;
import com.c88.member.api.MemberFeignClient;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.HashSet;
import java.util.Objects;

/**
 * 驗證碼（手機或電子郵件）認證授權提供者
 */
@Data
@Slf4j
public class CodeAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;
    private MemberFeignClient memberFeignClient;
    private RedisUtils redisUtils;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CodeAuthenticationToken authenticationToken = (CodeAuthenticationToken) authentication;
        String identity = (String) authenticationToken.getPrincipal();
        String code = (String) authenticationToken.getCredentials();

        String codeKey = identity + ':' + authenticationToken.getSessionId();
        Object correctCode = redisUtils.get(codeKey);
        // 验证码比对
        if (StrUtil.isBlank(code) || !Objects.equals(correctCode, code)) {
            log.error("error.codeInvalid, redis:" + correctCode + ", code:" + code);
            throw new BizException("error.codeInvalid");
        }
        // 比对成功删除缓存的验证码
        redisUtils.del(codeKey);

        UserDetails userDetails = ((MemberUserDetailsServiceImpl) userDetailsService).loadUserByMobile(identity);
        CodeAuthenticationToken result = new CodeAuthenticationToken(userDetails, authentication.getCredentials(), new HashSet<>());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

package com.c88.auth.security.core.userdetails.affiliate;

import cn.hutool.core.bean.BeanUtil;
import com.c88.affiliate.api.dto.AuthAffiliateDTO;
import com.c88.affiliate.api.feign.AffiliateFeignClient;
import com.c88.common.core.result.Result;
import com.c88.common.core.result.ResultCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 代理認證服務
 */
@Service("affiliateUserDetailsService")
@RequiredArgsConstructor
public class AffiliateUserDetailsServiceImpl implements UserDetailsService {

    private final AffiliateFeignClient affiliateFeignClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AffiliateUserDetails userDetails = null;
        Result<AuthAffiliateDTO> result = affiliateFeignClient.getAffiliateByUsername(username);
        if (Result.isSuccess(result)) {
            AuthAffiliateDTO user = result.getData();
            if (null != user) {
                userDetails = BeanUtil.copyProperties(user, AffiliateUserDetails.class);
            }
        }
        if (userDetails == null) {
            throw new UsernameNotFoundException(ResultCode.USER_NOT_EXIST.getMsg());
        } else if (!userDetails.isEnabled()) {
            throw new DisabledException("该账户已被禁用!");
        } else if (!userDetails.isAccountNonLocked()) {
            throw new LockedException("该账号已被锁定!");
        } else if (!userDetails.isAccountNonExpired()) {
            throw new AccountExpiredException("该账号已过期!");
        }
        return userDetails;
    }
}

package com.c88.auth.security.core.userdetails.member;


import cn.hutool.core.bean.BeanUtil;

import com.c88.common.core.result.Result;
import com.c88.common.core.result.ResultCode;

import com.c88.member.api.MemberFeignClient;
import com.c88.member.dto.AuthUserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 會員認證服務
 */
@Service("memberUserDetailsService")
@RequiredArgsConstructor
public class MemberUserDetailsServiceImpl implements UserDetailsService {

    private final MemberFeignClient memberFeignClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MemberUserDetails userDetails = null;
        Result<AuthUserDTO> result = memberFeignClient.getMemberByUserName(username);
        if (Result.isSuccess(result)) {
            AuthUserDTO user = result.getData();
            if (null != user) {
                userDetails = BeanUtil.copyProperties(user, MemberUserDetails.class);
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

    public UserDetails loadUserByMobile(String mobile) throws UsernameNotFoundException {
        MemberUserDetails userDetails = null;
        Result<AuthUserDTO> result = memberFeignClient.getMemberByMobile(mobile);
        if (Result.isSuccess(result)) {
            AuthUserDTO user = result.getData();
            if (null != user) {
                userDetails = BeanUtil.copyProperties(user, MemberUserDetails.class);
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

    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        MemberUserDetails userDetails = null;
        Result<AuthUserDTO> result = memberFeignClient.getMemberByEmail(email);
        if (Result.isSuccess(result)) {
            AuthUserDTO user = result.getData();
            if (null != user) {
                userDetails = BeanUtil.copyProperties(user, MemberUserDetails.class);
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

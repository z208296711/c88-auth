package com.c88.auth.security.extension.member;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class MemberToken extends UsernamePasswordAuthenticationToken {
    public MemberToken(Object principal, Object credentials) {
        super(principal, credentials);
    }
}

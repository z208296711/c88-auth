package com.c88.auth.security.extension.affiliate;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class AffiliateToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    public AffiliateToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}

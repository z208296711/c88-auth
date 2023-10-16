package com.c88.auth.security.extension.email;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * 手機驗證碼登入
 */
public class EmailCodeAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 550L;
    private final Object principal;
    private Object credentials;
    private String sessionId;
    private boolean isSms;

    public EmailCodeAuthenticationToken(Object principal, Object credentials, String sessionId, boolean isSms) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.sessionId = sessionId;
        this.isSms = isSms;
        this.setAuthenticated(false);
    }

    public EmailCodeAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public String getSessionId() {
        return this.sessionId;
    }

    public boolean isSms() {
        return this.isSms;
    }

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}

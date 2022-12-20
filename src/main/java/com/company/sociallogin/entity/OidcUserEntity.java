package com.company.sociallogin.entity;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import javax.persistence.MappedSuperclass;
import javax.persistence.Transient;
import java.util.Map;

@MappedSuperclass
public abstract class OidcUserEntity implements OidcUser {

    @Transient
    private OidcUserInfo userInfo;

    @Transient
    private OidcIdToken idToken;

    @Transient
    private Map<String, Object> attributes;

    @Transient
    private Map<String, Object> claims;

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return userInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setUserInfo(OidcUserInfo userInfo) {
        this.userInfo = userInfo;
    }

    public void setIdToken(OidcIdToken idToken) {
        this.idToken = idToken;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }
}

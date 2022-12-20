package com.company.sociallogin;

import com.company.sociallogin.security.FullAccessRole;
import com.company.sociallogin.security.OAuth2UserPersistence;
import io.jmix.core.JmixOrder;
import io.jmix.security.SecurityConfigurers;
import io.jmix.security.authentication.RoleGrantedAuthority;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.role.ResourceRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@Order(JmixOrder.HIGHEST_PRECEDENCE + 100)
public class OAuthSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ResourceRoleRepository resourceRoleRepository;

    @Autowired
    private OAuth2UserPersistence oidcUserPersistence;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.apply(SecurityConfigurers.uiSecurity())
                .and()
                .oauth2Login(configurer -> {
                            configurer.userInfoEndpoint()
                                    .userService(oauth2UserService())
                                    .oidcUserService(oidcUserService())
                                    .and()
                                    .successHandler((request, response, authentication) -> {
                                        //redirect to the main screen after successful authentication using auth provider
                                        new DefaultRedirectStrategy().sendRedirect(request, response, "/#main");
                                    });
                        }
                )
                .logout(configurer -> {
                    configurer.logoutSuccessHandler(oidcLogoutSuccessHandler());
                });
    }

    /**
     * Service responsible for loading OAuth2 users (GitHub uses OAuth2 protocol)
     */
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        return (userRequest) -> {
            // todo Implement user synchronization
            return null;
        };
    }

    /**
     * Service responsible for loading OIDC users (Google uses OIDC protocol)
     */
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return (userRequest) -> {
            // todo Implement user synchronization
            return null;
        };
    }

    /**
     * Builds granted authority list that grants access to the FullAccess role
     */
    private Collection<GrantedAuthority> getDefaultGrantedAuthorities() {
        ResourceRole fullAccessRole = resourceRoleRepository.getRoleByCode(FullAccessRole.CODE);
        RoleGrantedAuthority authority = RoleGrantedAuthority.ofResourceRole(fullAccessRole);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(authority);
        return authorities;
    }

    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("{baseUrl}");
        return successHandler;
    }
}

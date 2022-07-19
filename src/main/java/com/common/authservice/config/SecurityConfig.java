package com.common.authservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletResponse;

@SuppressWarnings("deprecation")
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, order = Ordered.HIGHEST_PRECEDENCE)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final AuthProperties authProperties;

    private final TokenStore tokenStore;

    private final TokenEnhancer tokenEnhancer;

    private final DaoAuthenticationProvider authenticationProvider;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.requiresChannel()
                .requestMatchers(r -> r.getHeader("X-Forwarded-Proto") != null)
                .requiresSecure().and()
                .anonymous().and()
                .authorizeRequests()
                .anyRequest().permitAll().and()
                .csrf().disable()
                .cors()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(unauthorizedEntryPoint())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    @Primary
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider);
    }

    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setSupportRefreshToken(authProperties.getSupportRefreshToken());
        defaultTokenServices.setReuseRefreshToken(authProperties.getReuseRefreshToken());
        defaultTokenServices.setAccessTokenValiditySeconds(authProperties.getTokenValiditySeconds());
        defaultTokenServices.setRefreshTokenValiditySeconds(authProperties.getRefreshTokenValiditySeconds());
        defaultTokenServices.setTokenStore(tokenStore);
        defaultTokenServices.setTokenEnhancer(tokenEnhancer);
        return defaultTokenServices;
    }
}

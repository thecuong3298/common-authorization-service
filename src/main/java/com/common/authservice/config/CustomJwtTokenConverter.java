package com.common.authservice.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component("customJwtTokenConverter")
@SuppressWarnings("deprecation")
public class CustomJwtTokenConverter extends JwtAccessTokenConverter {

    final RsaSigner signer;

    private Map<String, String> customHeaders = new HashMap<>();

    private static final String USERNAME = "user_name";

    private static final String ISSUE_AT = "iat";

    private static final String ROLES = "roles";

    private static final String AUTHORITIES = "authorities";

    private final JsonParser objectMapper = JsonParserFactory.create();

    private final AuthProperties authProperties;

    @Autowired
    public CustomJwtTokenConverter(KeyPair keyPair, AuthProperties authProperties) {
        super();
        this.authProperties = authProperties;
        super.setKeyPair(keyPair);
        this.signer = new RsaSigner((RSAPrivateKey) keyPair.getPrivate());
    }

    @Override
    protected String encode(OAuth2AccessToken accessToken,
                            OAuth2Authentication authentication) {
        String content;
        try {
            addCustomProperty(accessToken, authentication);
            content = this.objectMapper
                    .formatMap(getAccessTokenConverter()
                            .convertAccessToken(accessToken, authentication));
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Cannot convert access token to JSON", ex);
        }
        return JwtHelper.encode(
                content,
                this.signer,
                this.customHeaders).getEncoded();
    }

    public OAuth2AccessToken addCustomProperty(OAuth2AccessToken accessToken,
                                     OAuth2Authentication authentication) {
        final Map<String, Object> additionalInfo = new HashMap<>();
        String username = authentication.getName();
        additionalInfo.put(USERNAME, username);
        additionalInfo.put(ISSUE_AT, Instant.now().getEpochSecond());
        additionalInfo.put("iss", authProperties.getIss());
        additionalInfo.put(AUTHORITIES, authentication.getAuthorities().stream().map(
                GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        return accessToken;
    }
}

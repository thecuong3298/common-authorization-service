package com.common.authservice.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Configuration
@ConfigurationProperties(prefix = "spring.security.oauth2", ignoreUnknownFields = false)
public class AuthProperties {
  private String defaultClient;

  private String defaultSecret;

  private String iss;

  private Integer tokenValiditySeconds = 60 * 60;

  private Integer refreshTokenValiditySeconds = 5 * 60 * 60;

  private Boolean reuseRefreshToken = false;

  private Boolean supportRefreshToken = true;

  private List<String> grantType = Arrays.asList("password", "refresh_token");

  private Boolean setCookie = false;

  private Boolean cookieSecure = false;
}

package ru.ckib.oauth_demo.cfg;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2Login();
        // @formatter:on
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.spotifyClientRegistration());
    }

    private ClientRegistration spotifyClientRegistration() {
        // @formatter:off
        return ClientRegistration
                .withRegistrationId("google")
                .clientId("")
                .clientSecret("")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .scope("profile", "email")
                .tokenUri("https://www.googleapis.com/oauth2/v3/token")
                .userInfoUri("https://www.googleapis.com/userinfo/v2/me")
                .userNameAttributeName("email")
                .clientName("google")
                .build();
        // @formatter:on
    }

}

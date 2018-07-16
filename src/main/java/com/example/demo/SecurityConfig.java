package com.example.demo;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:application.yml")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private static Logger log = LoggerFactory.getLogger(SecurityConfig.class);

	private static List<String> clients = Arrays.asList("google", "facebook", "github", "slack");

	private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

	@Autowired
	private Environment env;

	@Override
	protected void configure(final HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/favicon.ico", "/oauth_login", "/loginFailure", "/oauth2/authorization/slack",
						"/oauth2/authorization/ghe")
				.permitAll().anyRequest().authenticated().and().oauth2Login()
				.clientRegistrationRepository(clientRegistrationRepository())
				.authorizedClientService(authorizedClientService())
				// .authorizationEndpoint()
				// .baseUri("/oauth2/authorize-client")
				// .authorizationRequestRepository(authorizationRequestRepository()).and()
				.loginPage("/oauth_login").defaultSuccessUrl("/loginSuccess", true).failureUrl("/loginFailure");
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService() {
		return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
	}

	@Bean
	public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {

		return new HttpSessionOAuth2AuthorizationRequestRepository();
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		List<ClientRegistration> registrations = clients.stream().map(c -> getRegistration(c))
				.filter(registration -> registration != null).collect(Collectors.toList());

		return new InMemoryClientRegistrationRepository(registrations);
	}

	private ClientRegistration getRegistration(String client) {

		log.info("OAuth: registering client " + client);

		final String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

		if (clientId == null) {
			return null;
		}

		final String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");

		if (client.equals("google")) {
			return CommonOAuth2Provider.GOOGLE.getBuilder(client).clientId(clientId).clientSecret(clientSecret).build();
		}

		if (client.equals("facebook")) {
			return CommonOAuth2Provider.FACEBOOK.getBuilder(client).clientId(clientId).clientSecret(clientSecret)
					.build();
		}

		if (client.equals("github")) {
			return CommonOAuth2Provider.GITHUB.getBuilder(client).clientId(clientId).clientSecret(clientSecret).build();
		}

		if (client.equals("slack")) {

//			final String clientName = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-name");
//			final String[] scopes = env.getProperty(CLIENT_PROPERTY_KEY + client + ".scope", String[].class);

			return this.getSlackBuilder(client).clientId(clientId).clientSecret(clientSecret).build();
			
		}

		return null;
	}

	private static final String DEFAULT_LOGIN_REDIRECT_URL = "{baseUrl}/login/oauth2/code/{registrationId}";

	private Builder getSlackBuilder(String registrationId) {
		
		ClientRegistration.Builder builder = getBuilder(
				registrationId, 
				ClientAuthenticationMethod.BASIC,
				DEFAULT_LOGIN_REDIRECT_URL);

		builder.scope("identify", "users.profile:read");
		builder.authorizationUri("https://slack.com/oauth/authorize");
		builder.tokenUri("https://api.slack.com/methods/oauth.token");
		builder.userInfoUri("https://slack.com/api/users.identity");
		builder.userNameAttributeName("id");
		builder.clientName("Slack");
		
		return builder;
	}

	private final ClientRegistration.Builder getBuilder(String registrationId, ClientAuthenticationMethod method,
			String redirectUri) {
		
		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
		
		builder.clientAuthenticationMethod(method);
		builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		builder.redirectUriTemplate(redirectUri);
		
		return builder;
	}
}

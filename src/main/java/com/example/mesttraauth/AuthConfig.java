package com.example.mesttraauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.List;

@EnableAuthorizationServer
@Configuration
public class AuthConfig extends AuthorizationServerConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final UserDetailsService userDetailsService;
	private final RedisConnectionFactory redisConnectionFactory;

	public AuthConfig (PasswordEncoder passwordEncoder,
	                   AuthenticationManager authenticationManager,
	                   UserDetailsService userDetailsService,
	                   RedisConnectionFactory redisConnectionFactory) {
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.userDetailsService = userDetailsService;
		this.redisConnectionFactory = redisConnectionFactory;
	}

	@Override
	public void configure (ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("password-credentials")
				.secret(passwordEncoder.encode("123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(20)  // 6H
				.refreshTokenValiditySeconds(30 * 24 * 60 * 60) // 30 Dias (em segundos)
		.and()
				.withClient("client-credentials") // não funciona com refresh token
				.secret(passwordEncoder.encode("123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("read")
		.and()
				.withClient("auth-code")
				.secret(passwordEncoder.encode("123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente")
				.accessTokenValiditySeconds(6 * 60 * 60)
		.and()
				.withClient("implicit-code") // nao funciona com refresh token
				.secret(passwordEncoder.encode("123"))
				.authorizedGrantTypes("implicit")
				.scopes("read")
				.redirectUris("http://aplicacao-cliente");
	}
	// http://auth.mesttra.local:8081/oauth/authorize?response_type=code&client_id=auth-code&state=abcF&redirect_uri=http://aplicacao-cliente
	// http://auth.mesttra.local:8081/oauth/authorize?response_type=code&client_id=auth-code&state=abcF&redirect_uri=http://aplicacao-cliente
	//+&code_challenge=123code_challenge_method=s256 ou plain

	@Override
	public void configure (AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()").allowFormAuthenticationForClients();
	}

	// Exclusivo para o fluxo de Password Credentials
	@Override
	public void configure (AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints
				.authenticationManager(authenticationManager)
				.userDetailsService(userDetailsService)
				.accessTokenConverter(jwtAccessTokenConverter())
				.tokenGranter(getTokenGranter(endpoints));
//				.tokenStore(new RedisTokenStore(redisConnectionFactory));
	}

	@Bean
	protected AccessTokenConverter jwtAccessTokenConverter () {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		jwtAccessTokenConverter.setSigningKey("123");
		return jwtAccessTokenConverter;
	}

	private TokenGranter getTokenGranter (AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthCodeTokenGranter = new PkceAuthCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(),
				endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());

		List<TokenGranter> tokenGranterList = List.of(pkceAuthCodeTokenGranter, endpoints.getTokenGranter());

		return new CompositeTokenGranter(tokenGranterList);
	}
}

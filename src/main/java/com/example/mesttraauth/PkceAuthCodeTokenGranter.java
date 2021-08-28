package com.example.mesttraauth;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.util.Assert;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

public class PkceAuthCodeTokenGranter extends AuthorizationCodeTokenGranter {

	public PkceAuthCodeTokenGranter (AuthorizationServerTokenServices tokenServices,
	                                 AuthorizationCodeServices authorizationCodeServices,
	                                 ClientDetailsService clientDetailsService,
	                                 OAuth2RequestFactory requestFactory) {
		super(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
	}

	@Override
	protected OAuth2Authentication getOAuth2Authentication (ClientDetails client, TokenRequest tokenRequest) {
		OAuth2Authentication oAuth2Authentication = super.getOAuth2Authentication(client, tokenRequest);
		OAuth2Request oAuth2Request = oAuth2Authentication.getOAuth2Request();

		Map<String, String> queryParameters = oAuth2Request.getRequestParameters();
		String codeChallenge = queryParameters.get("code_challenge");
		String codeChallengeMethod = queryParameters.get("code_challenge_method");
		String codeVerifier = queryParameters.get("code_verifier");

		if (nonNull(codeChallenge) || nonNull(codeChallengeMethod)) {

			if (isNull(codeVerifier) || codeVerifier.isBlank()) {
				throw new InvalidGrantException("Code verifier expected");
			}

			if (!validateCodeVerifier(codeVerifier, codeChallenge, codeChallengeMethod)) {
				throw new InvalidGrantException(codeVerifier + " não é compatível com o código do desafio");
			}
		}

		return oAuth2Authentication;
	}

	private boolean validateCodeVerifier (String codeVerifier, String codeChallenge, String codeChallengeMethod) {

		String generatedCodeChallenge = null;

		// Se o método é plain text, o codigo verificador é igual ao código desafio
		if ("plain".equalsIgnoreCase(codeChallengeMethod)) {
			generatedCodeChallenge = codeVerifier;
		} else if ("s256".equalsIgnoreCase(codeChallengeMethod)) {
			generatedCodeChallenge = hashSha256(codeVerifier);
		} else {
			throw new InvalidGrantException("O método " + codeChallengeMethod + " não é válido");
		}

		// Comparo o desafio gerado com o desafio da memória
		return generatedCodeChallenge.equals(codeChallenge);
	}

	private static String hashSha256 (String codeVerifier) {
		try {
			MessageDigest hasher = MessageDigest.getInstance("SHA-256");
			byte[] hash = hasher.digest(Utf8.encode(codeVerifier));
			return Base64.encodeBase64URLSafeString(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}

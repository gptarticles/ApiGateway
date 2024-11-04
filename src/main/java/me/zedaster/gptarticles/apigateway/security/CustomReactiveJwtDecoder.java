package me.zedaster.gptarticles.apigateway.security;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.text.ParseException;
import java.util.List;

/**
 * Filter that puts JWT claims to query params of request (if user is authorized by Bearer token)
 */
@Component
public class CustomReactiveJwtDecoder implements ReactiveJwtDecoder {
    private final Log logger = LogFactory.getLog(getClass());

    private final ReactiveJwtDecoder defaultDecoder;

    private final WebClient webClient;

    private final String tokenValidationUrl;

    public CustomReactiveJwtDecoder(@Value("${custom-oauth2.validation-url}") String tokenValidationUrl,
                                    WebClient.Builder webClientBuilder) {
        List<OAuth2TokenValidator<Jwt>> defaultValidators = List.of(new JwtTimestampValidator());
        this.defaultDecoder = createDefaultDecoder(defaultValidators);
        this.webClient = webClientBuilder.build();
        this.tokenValidationUrl = tokenValidationUrl;
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        return this.defaultDecoder
                .decode(token)
                .flatMap(jwt -> validateTokenRemotely(jwt).thenReturn(jwt));
    }


    /**
     * Validates a JWT token on the remote server
     * @param jwt The JWT token
     * @return Mono of void
     * @throws BadJwtException if the token is incorrect
     */
    private Mono<Void> validateTokenRemotely(Jwt jwt) {
        URI uri = UriComponentsBuilder.fromUriString(tokenValidationUrl)
                .queryParam("accessToken", jwt.getTokenValue())
                .build()
                .toUri();

        return webClient.get()
                .uri(uri)
                .retrieve()
                .onRawStatus(status -> status == 400, response -> Mono.error(createInvalidTokenException(uri)))
                .toBodilessEntity()
                .flatMap(response -> {
                    if (response.getStatusCode().isSameCodeAs(HttpStatusCode.valueOf(200))) {
                        return Mono.empty();
                    }
                    return Mono.error(new RuntimeException("Status code is not 200! It is " + response.getStatusCode().value()));
                })
                .onErrorResume(e -> Mono.error(new RuntimeException("Failed to validate token on the server!", e)))
                .then();
    }

    /**
     * Creates invalid token exception after query to the remote server
     * @param uri The URI of the request to the remote server
     * @return An instance of {@link BadJwtException}
     */
    private BadJwtException createInvalidTokenException(URI uri) {
        this.logger.debug("Token is invalid after validation on " + uri);
        return new BadJwtException("Token is invalid!");
    }

    /**
     * Creates a default JWT decoder from spring-oauth2-resource-server
     * @param defaultValidators Default validators for JWT tokens
     * @return the default reactive JWT decoder
     */
    private ReactiveJwtDecoder createDefaultDecoder(List<OAuth2TokenValidator<Jwt>> defaultValidators) {
        Converter<JWT, Mono<JWTClaimsSet>> claimProcessor = getStraightClaimProcessor();
        OAuth2TokenValidator<Jwt> validatorDecorator = new DelegatingOAuth2TokenValidator<>(defaultValidators);

        NimbusReactiveJwtDecoder jwtDecoder = new NimbusReactiveJwtDecoder(claimProcessor);
        jwtDecoder.setJwtValidator(validatorDecorator);
        return jwtDecoder;
    }

    /**
     * @return Lambda that just returns claims without any validation
     */
    private Converter<JWT, Mono<JWTClaimsSet>> getStraightClaimProcessor() {
        return jwt -> {
            try {
                return Mono.just(jwt.getJWTClaimsSet());
            } catch (ParseException e) {
                throw new RuntimeException("JWT Claims can't be parsed", e);
            }
        };
    }
}
package me.zedaster.gptarticles.apigateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Mono;

/**
 * Security configuration for the api gateway
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    /**
     * Custom decoder that validates token on auth server
     */
    private final CustomReactiveJwtDecoder customJwtDecoder;

    /**
     * Filter that puts JWT claims to query params of request (if user is authorized by Bearer token)
     */
    private final PayloadDeliveryFilter payloadDeliveryFilter;

    public SecurityConfig(CustomReactiveJwtDecoder customJwtDecoder, PayloadDeliveryFilter payloadDeliveryFilter) {
        this.customJwtDecoder = customJwtDecoder;
        this.payloadDeliveryFilter = payloadDeliveryFilter;
    }

    /**
     * Returns security filter chain.
     * @return Security filter chain.
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws Exception {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(authorize -> authorize
                        .pathMatchers("/protected/**").authenticated()
                        .anyExchange().permitAll())
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                        .jwt(jwtSpec -> jwtSpec.jwtDecoder(customJwtDecoder)))
                .addFilterAfter(payloadDeliveryFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public WebSessionManager webSessionManager() {
        // Emulate SessionCreationPolicy.STATELESS
        return exchange -> Mono.empty();
    }
}

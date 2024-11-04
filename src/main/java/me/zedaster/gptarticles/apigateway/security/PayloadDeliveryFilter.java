package me.zedaster.gptarticles.apigateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;

/**
 * Filter that puts JWT claims to query parameters of request (if user is authorized by Bearer token)
 */
@Component
public class PayloadDeliveryFilter implements WebFilter {
    /**
     * Prefix for query parameters of JWT claims
     */
    private final String claimsQueryPrefix;

    public PayloadDeliveryFilter(@Value("${custom-oauth2.claims-query-prefix}") String claimsQueryPrefix) {
        this.claimsQueryPrefix = claimsQueryPrefix;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return exchange.getPrincipal()
                .filter(principal -> principal instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(jwt ->
                        getRequestCopyWithClaims(exchange.getRequest(), jwt.getTokenAttributes()))
                .map(newRequest -> exchange.mutate().request(newRequest).build())
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    /**
     * Copies a request and puts the JWT claims as query parameters
     * @param request The request
     * @param claims The JWT claims
     * @return The modified copy of the request
     */
    private ServerHttpRequest getRequestCopyWithClaims(ServerHttpRequest request, Map<String, Object> claims) {
        UriComponentsBuilder newUriBuilder = UriComponentsBuilder.fromUri(request.getURI());

        for (Map.Entry<String, Object> claim : claims.entrySet()) {
            newUriBuilder.queryParam(claimsQueryPrefix + claim.getKey(), claim.getValue());
        }
        URI newUri = newUriBuilder.build().toUri();
        return request.mutate()
                .uri(newUri)
                .build();
    }
}

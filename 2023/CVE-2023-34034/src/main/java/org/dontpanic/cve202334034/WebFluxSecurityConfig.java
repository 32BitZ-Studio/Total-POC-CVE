package org.dontpanic.cve202334034;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class WebFluxSecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // disable CSRF
                .csrf().disable()

                // add AuthenticationWebFilter and set the handler
                .formLogin()
                .authenticationSuccessHandler(new WebFilterChainServerAuthenticationSuccessHandler())
                .authenticationFailureHandler(((webFilterExchange, exception) -> Mono.error(exception)))


                .and()
                .authorizeExchange()
                .pathMatchers("admin/**")
                .hasRole("ADMIN")

                .and()
                .authorizeExchange()
                .anyExchange()
                .permitAll();
        return http.build();
    }
}

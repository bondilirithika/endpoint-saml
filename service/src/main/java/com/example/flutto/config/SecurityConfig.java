package com.example.flutto.config;

import com.example.flutto.filter.JwtAuthenticationFilter;
//import com.example.flutto.filter.SamlRedirectUriFilter;
import com.example.flutto.service.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
 
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtService jwtService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtService jwtService, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtService = jwtService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // <--- Disable CSRF for now
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(authz -> authz
                .requestMatchers(
                    "/", "/login", "/error", "/css/**", "/js/**", "/favicon.ico",
                    "/api/auth/store-redirect", // <-- add this line
                    "/api/auth/validate",       // (optional, for JWT validation)
                    "/api/auth/login-url",      // (optional, if you use it)
                    "/api/auth/logout-url"      // (optional, if you use it)
                ).permitAll()
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                // .loginPage("/login")
                .successHandler(samlSuccessHandler())
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("jwt", "JSESSIONID")
                .addLogoutHandler((request, response, authentication) -> {
                    Cookie cookie = new Cookie("jwt", null);
                    cookie.setMaxAge(0);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                    SecurityContextHolder.clearContext();
                })
            );

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler samlSuccessHandler() {
        return (request, response, authentication) -> {
            Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

            String jwt = jwtService.generateToken(authentication);

            Cookie jwtCookie = new Cookie("jwt", jwt);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(false); // Set to true in production with HTTPS
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(86400); // 24 hours

            response.addCookie(jwtCookie);

            String redirectUri = null;
            HttpSession session = request.getSession(false);
            if (session != null) {
                redirectUri = (String) session.getAttribute("SAML_REDIRECT_URI");
                logger.info("SAML SuccessHandler: Found redirectUri in session: {}", redirectUri);
                session.removeAttribute("SAML_REDIRECT_URI");
            }
            if (redirectUri == null || redirectUri.isBlank()) {
                redirectUri = "/";
                logger.warn("SAML SuccessHandler: No redirectUri found, using fallback: /");
            }

            String redirectWithJwt = redirectUri + (redirectUri.contains("?") ? "&" : "?") + "jwt=" + jwt;
            logger.info("SAML SuccessHandler: Redirecting to: {}", redirectWithJwt);
            response.sendRedirect(redirectWithJwt);
        };
    }

    // @Bean
    // public FilterRegistrationBean<SamlRedirectUriFilter> samlRedirectUriFilterRegistration(SamlRedirectUriFilter filter) {
    //     FilterRegistrationBean<SamlRedirectUriFilter> registration = new FilterRegistrationBean<>(filter);
    //     registration.addUrlPatterns("/*"); // <-- Run for all requests
    //     registration.setOrder(0); // Run early
    //     return registration;
    // }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("http://localhost:3000","https://sacramento-nt-grows-poster.trycloudflare.com")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowCredentials(true);
            }
        };
    }
}
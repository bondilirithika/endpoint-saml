package com.example.flutto.controller;

import com.example.flutto.service.JwtService;
import io.jsonwebtoken.Claims;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.Cookie;

@RestController
@RequestMapping("/api/auth")
public class AuthApiController {

    private final JwtService jwtService;

    public AuthApiController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // 1. Get SAML login URL for client app
    @GetMapping("/login-url")
    public ResponseEntity<?> getLoginUrl(@RequestParam String redirectUri) {
        String encodedRedirect = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        String loginUrl = "/saml2/authenticate/google?redirect_uri=" + encodedRedirect;
        Map<String, String> response = new HashMap<>();
        response.put("loginUrl", loginUrl);
        return ResponseEntity.ok(response);
    }

    // 2. Validate JWT
    @GetMapping("/validate")
    public ResponseEntity<?> validate(@RequestParam String token) {
        Map<String, Object> response = new HashMap<>();
        if (token == null || !jwtService.isTokenValid(token)) {
            response.put("valid", false);
            return ResponseEntity.ok(response);
        }
        Claims claims = jwtService.extractClaims(token);
        response.put("valid", true);
        response.put("username", claims.get("username"));
        response.put("email", claims.get("email"));
        response.put("roles", claims.get("roles"));
        return ResponseEntity.ok(response);
    }

    // 3. Get logout URL for client app
    @GetMapping("/logout-url")
    public ResponseEntity<?> getLogoutUrl(@RequestParam String redirectUri) {
        String encodedRedirect = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        String logoutUrl = "/custom-logout?redirect_uri=" + encodedRedirect;
        Map<String, String> response = new HashMap<>();
        response.put("logoutUrl", logoutUrl);
        return ResponseEntity.ok(response);
    }

    // 4. Store redirect URI in session
    @PostMapping("/store-redirect")
    public ResponseEntity<?> storeRedirectUri(@RequestParam String redirectUri, HttpSession session) {
        session.setAttribute("SAML_REDIRECT_URI", redirectUri);
        return ResponseEntity.ok().build();
    }

    // Custom logout endpoint
    @GetMapping("/custom-logout")
    public void customLogout(@RequestParam("redirect_uri") String redirectUri,
                             HttpServletRequest request,
                             HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            System.out.println("Invalidating session: " + session.getId());
            session.invalidate();
        } else {
            System.out.println("No session to invalidate.");
        }

        Cookie cookie = new Cookie("jwt", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);

        response.sendRedirect(redirectUri);
    }
}
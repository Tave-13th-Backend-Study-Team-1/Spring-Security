package com.example.kakaoLogin;

import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import java.util.Base64;


import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class KakaoLoginController {

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String kakaoRedirectUri;

    @GetMapping("/login")
    public void tologin(){
        String tokenUrl = "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=dffdc9224a360a9d9d908ca4942cff8d&redirect_uri=http://localhost:8080/api/cccc";
    }


    @GetMapping("/api/cccc")
    public String getAccessToken(@RequestParam("code") String code) {
        System.out.println("code = " + code);

        // Kakao OAuth2 Token Endpoint
        String tokenUrl = "https://kauth.kakao.com/oauth/token";

        // Request body parameters
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "authorization_code");
        requestBody.add("client_id", kakaoClientId); // Replace with your Kakao client ID
        requestBody.add("redirect_uri", kakaoRedirectUri); // Replace with your redirect URI
        requestBody.add("code", code);

        // Build the request
        Mono<String> responseMono = webClientBuilder.build()
                .post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(requestBody))
                .retrieve()
                .bodyToMono(String.class);

        // Extract access token and ID token from the response
        String responseEntity = responseMono.block();

        System.out.println("responseEntity = " + responseEntity);
        String idToken = extractIdToken(responseEntity);
        String nickname = extractNicknameFromIdToken(idToken);

        System.out.println("Nickname: " + nickname);

        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("nickname", nickname);
        String password = "12345";

        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");

        // 사용자가 인증될 때 사용될 인증 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                nickname, password, Collections.singleton(authority));


        // Set authentication in SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);

        System.out.println("SecurityContextHolder.getContext() = " + SecurityContextHolder.getContext());


        return "Success";
    }

    private String extractIdToken(String responseBody) {
        JSONObject responseJson = (JSONObject) JSONValue.parse(responseBody);
        String idToken = (String) responseJson.get("id_token");
        return idToken;
    }

    private String extractNicknameFromIdToken(String idToken) {
        // Decode the ID token
        String[] tokenSegments = idToken.split("\\.");
        String encodedPayload = tokenSegments[1];
        String payload = new String(Base64.getDecoder().decode(encodedPayload));

        // Parse JSON payload to extract nickname
        JSONObject payloadJson = (JSONObject) JSONValue.parse(payload);
        String nickname = (String) payloadJson.get("nickname");

        return nickname;
    }

    @GetMapping("/test")
    public String test(){
        return "로그인 성공";
    }
}


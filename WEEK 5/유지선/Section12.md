# Section 12

## Github를 이용한 실습

### 1. 깃허브 클라이언트 등록

- 등록 이후 제공되는 Client Id와 Client Secret은 따로 기록 필요

### 2. oauth2이용을 위한 의존성 추가

```groovy
implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
```

- oauth2-client
  - oauth2 클라이언트 역할 실행 가능

### 3. Controller 설정

```Java
@GetMapping("/")
public String main(OAuth2AuthenticationToken token){
    System.out.println(token.getPrincipal());
    return "secure.html";
}
```

- OAuth2AutenticationToken
  - 엔드 유저에 대한 모든 세부 사항 명시 \
    -> 더 많은 세부사항 파악 가능

### 4. OAuth2 Config 설정

```Java
@Configuration
public class SpringSecOAUTH2GitHubConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests)->requests.anyRequest().authenticated())
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRepository() {
        ClientRegistration clientReg = clientRegistration();
        return new InMemoryClientRegistrationRepository(clientReg);
    }

    private ClientRegistration clientRegistration() {
		return CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("8cf67ab304dc500092e3")
	           .clientSecret("6e6f91851c864684af2f91eaa08fb5041162768e").build();
	 }

}
```

- `.oauth2()`
  - outh2 로그인을 다루겠다는 의미
- `ClientRegistrationRepository`
  - 클라이언트 등록 유형 리포지토리에 대한 bean 생성
- `CommonOAuth2Provider`
  - builder형태의 사용을 위하여 Google, Github, Facebook, Okta 유형 제공
  - `scope`, `authorizationUri`, `tokenUri`, `jwtSetUri`, `issuerUri`, `userINfoUri`, `userNameAttributeName`, `clientName`

### 특징

- 다른 서비스의 auth 서버를 이용 \
  -> 현재 서비스에서의 권한 설정을 위해서는 새롭게 auth 서버를 설정해야 함

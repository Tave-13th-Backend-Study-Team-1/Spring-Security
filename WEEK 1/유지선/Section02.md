# Section 2

### 설정할 Backend Rest API

- 공개적인 api : `/contact` `/notices`
- 보안 적용 api : `/myAccount` `/myBalance` `/myLoans` `/myCards`

## 보안 요구사항 정의

`defaultSecurityFilterChain()` 사용하여 엔드포인트 URL 관리

```Java
@Bean
@Order(SecurityProperties.BASIC_AUTH_ORDER)
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
	http.authorizeHttpRequests().anyRequest().authenticated();
	http.formLogin();
	http.httpBasic();
	reuturn http.build();
}
```

- `authorizeHttpRequests()` 사용 시 `AuthorizationFilter` 적용 가능
- `formLogin()` 사용 시 `UsernamePassworduthenticationFilter` 등의 여러 필터 적용 가능
- 자체적인 보안 요구사항을 정의하려고 하는 경우 사용자 정의 `SecurityFilterChain` 타입 빈 생성 필요
  - 생성 시 `defaultSecurityFilterChain` 은 적용되지 않음

### 일부 api는 모두 허용하고 일부 api는 인증을 요구하는 경우

```Java
http.authorizeRequests()
            .requestMatchers("/myAcount", "/myBalance", "/myLoans", "/myCards").authenticated()
            .requestMatchers("/notices", "/contact").permitAll()
```

- `.authenticated()` : 인증 요구

### 모든 요청을 거절하는 경우

```Java
httpSecurity.authorizeHttpRequests().anyRequest().denyAll();
```

- 서버를 종료하는 대신에 모든 요청을 막을 수 있는 방법
  - Spring의 `Profile`의 도움을 받아 `애플리케이션 배포 환경` 을 조건으로 `Bean 생성 여부` 선택 가능
- 클라이언트가 자격 증명 완료 시 `403 error` 반환
  - 자격 증명을 완료한 이후 보안 api 조건 실행

### 모든 요청을 허용하는 경우

```Java
httpSecurity.authorizeHttpRequests().anyRequest().permitAll();
```

- 개발과 테스트 환경에서 모두 허용해야 하는 경우 사용하는 방법

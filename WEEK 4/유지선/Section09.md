# Section 9

### 클라이언트에서 현재 이용되는 토큰

- JSESSIONID
  - 성공적으로 로그인 완료 시 생성되는 쿠키 값 \
    -> 이후 모든 요청에서 엔드 유저가 자격증명을 입력하지 않아도 됨
  - 백엔드에 요청을 할 때 마다 해당 쿠키는 브라우저에 의해 자동으로 첨부될 것
- XSRF 토큰
  - 클라이언트 애플리케이션에 의해 header 안으로 넣어짐
    - CSRF 공격의 보안으로 인한 요청 실패를 막기 위함

### JSESSIONID의 단점

- 해당 토큰은 유저 데이터를 가지고 있지 않음
  - 현재 기준 무작위로 생성된 값
- 엔드 유저가 브라우저를 닫지 않아 엔드 유저 세션이 유지될 경우 \
  -> 브라우저에 저장된 쿠키로 악용될 수 있음

## 토큰

- 범용 고유 식별자 (UUID) 형식의 일반 문자열
- JWT 토큰의 한 종류 (Json Web Token)
- 일반적으로 엔드 유저의 인증 완료 시 로그인 작업 중 처음 생성

### 토큰 사용 흐름

- 엔드 유저가 백엔드 애플리케이션에 본인의 ID와 비밀번호를 이용하여 로그인 시도
- 자격증명이 유효한 경우 \
  -> 백엔드 애플리케이션 또는 승인 서버가 토큰 생성 \
  -> 클라이언트에게 토큰 전달
- 보안된 api를 접속할 때마다 클라이언트 애플리케이션은 반드시 같은 토큰을 백엔드 서버로 보냄

### 토큰 사용 시 장점

- 토큰을 이용할 때마다 로그인 중에만 실제 자격증명을 백엔드 애플리케이션에 보내야 함 \
  -> 모든 요청에 실제 자격증명을 공유하지 않아도 됨
- 어떤 해커에 의해 공격당한다면 토큰만 무력화시키면 됨
- 기업의 요구사항에 따라 토큰 수명 결정 가능
- 토큰에 유저 정보 혹은 역할 정보 저장 가능
- 토큰 재사용 가능
  - 같은 조직 내에서 반복적인 로그인 불필요 \
    -> 마이크로서비스 환경에서 stateless로 있을 수 있음 - stateless - 클러스터 환경이 같은 애플리케이션의 여러 인스턴스가 있을 때 로그인 중 요청이 1번 인스턴스로 가고 이후 요청들은 1번 인스턴스로만 가지 않아도 됨

## JWT 토큰

- Json Web Token
  - 내부적으로 데이터를 JSON 형식으로 유지
- 웹 요청에 사용됨
  - REST 서비스의 도움으로 JSON 형식으로 통신하기 위해 설계
- 인증 및 인가 중 사용 가능
- 토큰 자체 내부에서 유저와 관련된 데이터를 저장 및 공유할 수 있도록 도와줌
- 기본적인 접근 : JWT 토큰이 처음 생성될 때마다 데이터베이스 혹은 캐시 속에 저장 \
  -> 클라이언트에서 특정 JWT 토큰을 사용하는 모든 후속 요청에서 저장된 것과 동일한지 확인

### JWT 토큰의 구조

- 세 부분으로 나누어짐
  - 마침표 혹은 점으로 구분
- Header
  - 토큰에 대한 정보인 메타데이터 저장
    - 주로 알고리즘이 무엇인지,
    - 토큰의 종류가 무엇인지,
    - 생성하며 사용된 토큰의 형식
  ```Json
  {
      "alg" : "HS256",
      "typ" : "JWT"
  }
  ```
  - 알고리즘은 HS256 사용
  - 토큰의 형식은 JWT
  - 이후 위 내용을 Base64로 인코딩
- Payload
  - 저장을 원하는 유저에 대한 모든 정보 저장 가능
    - 이름, 이메일, 역할, 토큰 발행 시 만료 시간, 토큰에 서명한 자
  - Base64로 인코딩 된 모습의 전송됨
- Signature (Optional)
  - 디지털 서명 시 나중에 누군가 토큰을 조작하려고 하면 쉽게 감지 가능
    - 클라이언트 애플리케이션이 토큰과 방화벽 속 모든 소통을 조작하지 않을 것이라는 신뢰가 있다면 필요 없음
  - JWT 토큰 조작 방지 방법
    - SHA-256와 같이 알고리즘 중 하나의 도움을 받음 \
      -> 해당 비밀 값은 JWT 토큰을 발행하는 백엔드 애플리케이션만 알 수 있음 - 전달된 덷이터를 기반으로 한 무작위 해시 문자열
  - 누군가 토큰 조작시 세션 무효화

## 프로젝트에 JWT 적용

### JWT 의존성 추가

```groovy
dependencies {
  implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
  implementation 'io.jsonwebtoken:jjwt-impl:0.11.5'
  implementation 'io.jsonwebtoken:jjwt-jackson:0.11.5'
}
```

### JWT 토큰을 사용하여 세션 사용을 중지

- `JSESSIONID`를 생성하지 말고 session Id 세부 정보도 사용하지 말라고 전달해야 함 \
  -> `sessionManagement()` 메소드 호출 후 매개변수를 받지 않음
- SesseionCreationPolicy.STATELESS 설정
  - JSESSIONID와 history depresetions를 생성하지 않도록 설정

```Java
http.sessionManagement(sessionManagement -> {
            sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });
```

### JWT 토큰이 클라이언트에게 잘 가도록 설정

- CORS 설정에서 JWT 토큰 전송을 위하여 헤더를 노출해도 되도록 설정

```Java
config.setExposedHeaders(Arrays.asList("Authorization"));
```

- 보내려는 헤더의 이름이 Authroization

> **CSRF 토큰에 대해서는 이 설정을 하지 않는 이유**
> CSRF 토큰은 프레임워크에서 제공하는 헤더
> 여기서의 Authorization의 경우 직접 작성한 헤더

### JWT 로직 적용

- 로그인이 성공적으로 완료될 때마다 JWT 토큰을 생성해야 함
- JWT 토큰 생성 필터 : `JWTTokenGeneratorFilter`

  - 요청이 들어오고 한 번만 실행되어야 함 \
    -> OncePerRequestFilter 확장
  - BasicAuthenticationFilter 다음에 실행되도록 적용

  ```Java
  public class JWTTokenGeneratorFilter extends OncePerRequestFilter {
      @Override
      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                      FilterChain filterChain) throws ServletException, IOException {
          Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
          if (null != authentication) {
              SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
              String jwt = Jwts.builder().issuer("Eazy Bank").subject("JWT Token")
                      .claim("username", authentication.getName())
                      .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                      .issuedAt(new Date())
                      .expiration(new Date((new Date()).getTime() + 30000000))
                      .signWith(key).compact();
              response.setHeader(SecurityConstants.JWT_HEADER, jwt);
          }

          filterChain.doFilter(request, response);
      }

      @Override
      protected boolean shouldNotFilter(HttpServletRequest request) {
          return !request.getServletPath().equals("/user");
      }

      private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
          Set<String> authoritiesSet = new HashSet<>();
          for (GrantedAuthority authority : collection) {
              authoritiesSet.add(authority.getAuthority());
          }
          return String.join(",", authoritiesSet);
      }

  }
  ```

  - `Authentication authentication = SecurityContextHolder.getContext().getAuthentication();`
    - `BasicAuthenticationFilter`를 통하여 인증이 완료된 상태 \
      -> `SecurityContextHolder`를 통하여 인증 정보를 가져와 인증 객체에 저장
  - `SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));`
    - 인증 객체가 null 이 아닌 경우
    - `SecurityConstants` 내의 비밀 값을 기반으로 비밀 키 생성
      - 서버 측에서만 알고 있어야 함
      - 실제 상황에에서는 DevOps 팀에 요청하여 이 값을 런타임 중에 주입하도록 해야 함
        - CI/CD (Github Actions, Jenkins)를 이용한 환경 변수 설정
        - 프로덕션 서버에서의 환경 변수 구성
  - builder 패턴을 이용한 jwt 토큰 구성
    - `issuer`
      - 토큰 발행자
    - `claim`
      - 사용자 이름 가져오기 가능
      - 사용자가 가지고 있는 권한 불러오기 가능
    - `issuedAt`
      - 토큰 발행 일자 추가
    - `expiration`
      - 토큰 만료 일자 설정
    - `signWith`
      - 디지털 서명 진행
  - `shouldNotFilter()` 적용
    - jwt 토큰 생성 필터는 오직 로그인 과정 중에만 실행되어야 함 \
      -> 후속 요청에서 토큰이 계속해서 생성되는 것을 막음 \
      -> 로그인 경로인 `/users` 일때만 필터 실행

- JWT 검증 필터 : `JWTTokenValidatorFilter`

  ```Java
  public class JWTTokenValidatorFilter  extends OncePerRequestFilter {
      @Override
      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                      FilterChain filterChain) throws ServletException, IOException {
          String jwt = request.getHeader(SecurityConstants.JWT_HEADER);
          if (null != jwt) {
              try {
                  SecretKey key = Keys.hmacShaKeyFor(
                          SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));

                  Claims claims = Jwts.parser()
                          .verifyWith(key)
                          .build()
                          .parseSignedClaims(jwt)
                          .getPayload();
                  String username = String.valueOf(claims.get("username"));
                  String authorities = (String) claims.get("authorities");
                  Authentication auth = new UsernamePasswordAuthenticationToken(username, null,
                          AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                  SecurityContextHolder.getContext().setAuthentication(auth);
              } catch (Exception e) {
                  throw new BadCredentialsException("Invalid Token received!");
              }
          }
          filterChain.doFilter(request, response);
      }
      @Override
      protected boolean shouldNotFilter(HttpServletRequest request) {
          return request.getServletPath().equals("/user");
      }
  }
  ```

  - `String jwt = request.getHeader(SecurityConstants.JWT_HEADER);`
    - 헤더에서 `JWT_HEADER` 이름에 해당한느 jwt토큰을 가져옴
  - `SecretKey key = Keys.hmacShaKeyFor()`
    - 비밀키를 다시 만들고 요청에서 jwt토큰에서 가져온 값과 비교 후 유효한지 확인한 후 사용자 정보를 가져옴
    - `parserBuilder`를 통하여 비교 실행
  - `new UsernamePasswordAuthenticationToken(username, null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));`
    - jwt 토큰에서 빼온 정보를 가지고 인증 객체 생성 \
      -> `SecurityContextHolder`에 설정
  - `shouldNotFilter()`
    - /user 경로 빼고는 모두 적용되도록 설정

### 클라이언트 코드 설정

- 유저 검증 로직에서 세션에서 Authorization 이름을 가진 jwt 토큰을 보내도록 설정

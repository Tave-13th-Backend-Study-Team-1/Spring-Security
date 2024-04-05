# Section 08

## Custom Security Filter

### Custom Filter를 사용하는 이유

- 특정 상황이나 클라이언트의 요구 사항에 따라 인증 및 권한 부여 흐름 중 일부를 하우스 키핑 활동에 수행해야 함
  - 인증 전에 몇 가지의 입력 검증 수행
  - 요청 추적, 감사 및 보고 세부 정보 추가
  - 시스템에 들어가려고 하는 엔드 유저의 일부 세부 정보를 로그에 기록
    - IP 주소, 국가 세부 정보 등
  - 인증 이전 입력 데이터의 암호화 및 복호화 실행
  - OTP를 사용한 다중 인자 인증 강제

### Custom Filter 종류

- HTTP 필터
  - 모든 응답 혹은 요청을 가로채길 바라는 경우
  - 특수 유형의 서블릿
- 유저 인증 중에 사용되는 몇 가지 내장 필터
  - `UsernamePasswordAuthenticationFilter`
  - `BasicAuthenticationFilter`
  - `DefaultLoginPageGeneratingFilter`

### Filter의 특징

- 인증을 시도하려고 할 때 실행되는 필터의 수가 많음
  - 자체적인 역할과 책임을 가지는 10 개 이상의 필터 실행
- 필터가 실행되는 방식은 연쇄적

### 필터를 로그 또는 콘솔에서 확인하는 방법

- Spring Boot 애플리케이션의 주 클래스 내에 `@EnableWebSecurity` 사용
  - (debug = true) 설정
  ```Java
  public class FilterChainProxy extends GenericFilterBean {
      private static final class VirtualFilterChain implements FilterChain {
          @Override
  	public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
  		if (this.currentPosition == this.size) {
  			this.originalChain.doFilter(request, response);
  			return;
  		}
  		this.currentPosition++;
  		Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
  		if (logger.isTraceEnabled()) {
  			String name = nextFilter.getClass().getSimpleName();
  			logger.trace(LogMessage.format("Invoking %s (%d/%d)", name, this.currentPosition, this.size));
  		}
  		nextFilter.doFilter(request, response, this);
  	}
      }
  }
  ```
  - `currentPosition`값을 통해 현재 위치 필터 추적
    - `currentPosition` 값이 size 값과 일치할 경우 필터 순회 종료 \
      -> `originalChain.doFilter` 호출
- `application.properties` 파일 내에 디버그 로깅을 가능하게 하는 `FilterChainProxy` 활성화
  - `FilterChainProxy`
    - Spring Security의 내장 필터 연결 로직
    - 실제 웹 애플리케이션에서 실행 시 엔드 유저의 정보까지 출력 가능 \
      -> 사용 자제
  ```
  logging.level.org.springframework.security.web.FilterChainProxy=DEBUG
  ```

## Spring Security 내부 필터 실행

- 현재 설정 기준 17개의 필터가 적용되는 중
  - `FilterChainProxy`의 `VirtualFilterChain`이 size값
  ```
  Security filter chain : [
      DisableEncodeUrlFilter
      WebAsyncManagerintegrationFilter
      SecurityContextHolderFilter
      HeaderWriterFilter
      CorsFilter
      CsrfFilter
      LogoutFilter
      UsernamePasswordAuthenticationFilter
      DefaultLogoutPageGeneratingFilter
      BasicAuthenticationFilter
      RequestCacheAwareFilter
      SecurityContextHolderAwareRequestFilter
      AnonymousAuthenticationFilter
      AnonymousAuthenticationFilter
      SessionManagementFilter
      ExceptionTranslationFilter
      FilterSecurityInterceptor
  ]
  ```

## Custom Filter 적용 방법

### 1. Custom Filter 생성

- jarkarta.servlet 패키지 내의 `Filter` 인터페이스 확장

```Java
public interface Filter {
  default void init(FilterConfig filterConfig) throws ServletException {
    }
  void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException;

  default void destroy() {
    }
}
```

- `init()`
  - 기본적으로 필터를 진행할 때 실행
  - 오버라이드하여 구현하지 않아도 됨
- `doFilter()`
  - 실행할 로직 작성
  - 세 가지 입력 매개변수 제공 혹은 엑세스
    - `ServletRequest`
      - 엔드 유저로부터 오는 HTTP input 요청
    - `ServletResponse`
      - 엔드 유저나 클라이언트에게 다시 보낼 HTTP 응답
    - `FilterChain`
      - 정의된 순서대로 실행되는 필터들의 집합 \
        -> 다음 가능한 필터를 불러올 것
- `destroy()`
  - 특정 필터가 서블릿 컨테이너에서 destroye될 때 실행
  - 오버라이드하여 구현하지 않아도 됨

### 2. 생성된 Custom Filter의 적용

- `addFilterBefore(filter, class)`
  - 특정 필터 class 이전에 지정 필터 실행
- `addFilterAfter(filter, class)`
  - 특정 필터 class 이후에 지정 필터 실행
- `addFilterAt(filter, class)`
  - 특정 필터 class와 동일한 위치에서 지정 필터 실행

### 현재 사용되는 여러 커스텀 필터

- `CorsFilter`, `CsrfFilter`, `BasicAuthenticationFilter`
  - 자격 증명 추출 이후 실제 인증 발생 \
    -> 커스텀 필터를 만들고 이를 `BasicAuthenticaitonFilter` 이전에 적용되도록 구현

```Java
public class RequestValidationBeforeFilter implements Filter {
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";
    private Charset credentialsCharset = StandardCharsets.UTF_8;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String header = req.getHeader(AUTHORIZATION);
        if (header != null) {
            header = header.trim();
            if (StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
                byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
                byte[] decoded;
                try {
                    decoded = Base64.getDecoder().decode(base64Token);
                    String token = new String(decoded, credentialsCharset);
                    int delim = token.indexOf(":");
                    if (delim == -1) {
                        throw new BadCredentialsException("Invalid basic authentication token");
                    }
                    String email = token.substring(0, delim);
                    if (email.toLowerCase().contains("test")) {
                        res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        return;
                    }
                } catch (IllegalArgumentException e) {
                    throw new BadCredentialsException("Failed to decode basic authentication token");
                }
            }
        }
        chain.doFilter(request, response);
    }
}
```

- request와 respone를 각각 `HttpServletRequest`와 `HttpServletResponse`로 변환
- 클라이언트를 위한 Authorization header 확보 \
  -> header 값 내에 6번째 부분부터 추출 (BASIC 제외) \
  -> `base64Token` 객체로 확보
- 디코딩 이후 : 로 분리
- Authentication header 내에서 가장 첫 두 값 추출 시도 : username(email) \
  -> email에 test 값이 있는지 확인 \
  -> 그렇다면 400 에러 반환
  -> 그렇지 않다면 다음 필터 진행
- 이후 SecurityConfig 파일에서 필터 순서 적용 진행
  ```Java
  .addFilterBefore(new RequestValidateionBeforeFilter(), BasicAuthenticationFilter.class)
  ```

### 유저 인증이 성공적임을 알리고 유저가 보유한 권한 로그 출력 Filter

- `addFilterAfter()`

  ```Java
  public class AuthoritiesLoggingAfterFilter implements Filter {
      private final Logger LOG =
              Logger.getLogger(AuthoritiesLoggingAfterFilter.class.getName());

      @Override
      public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
              throws IOException, ServletException {

          Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
          if (null != authentication) {
              LOG.info("User " + authentication.getName() + " is successfully authenticated and "
                      + "has the authorities " + authentication.getAuthorities().toString());
          }
          chain.doFilter(request, response);
      }
  }
  ```

  - 인증된 유저의 세부정보가 `Securitycontext`에 저장된 상태 \
    -> `SecurityContextHolder.getContext().getAuthentication()`
    - 세부 정보를 인증 객체로 제공
  - 인증 객체가 null이 아니라면 유저 권한 로깅 작업 진행

  ```Java
  .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
  ```

### 인증 중임을 나타내는 filter

- `addFilterAt()`

  - 내부적으로 동일한 위치에 적용된 필터들을 무작위의 순서로 진행
  - 사용 예시
    - 인증 프로세스 중에 사용자에게 인증이 진행 중임을 알리기 위해 이메일을 보냄
    - 인증이 성공적이라고 엔드 유저에게 알림
    - 내부 응용 프로그램에 알림을 보냄

  ```Java
  public class AuthoritiesLoggingAtFilter implements Filter {
      private final Logger LOG =
              Logger.getLogger(AuthoritiesLoggingAtFilter.class.getName());

      @Override
      public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
              throws IOException, ServletException {
          LOG.info("Authentication Validation is in progress");
          chain.doFilter(request, response);
      }
  }
  ```

## Custom Filter 생성할 때 사용할 수 있는 다른 옵션

### `GenericFilterBean`

- 추상 클래스
- web.xml이나 배포 설명자 내에서 구성한 모든 설정 매개변수, 초기 매개변수 및 서블릿 컨텍스트 매개변수의 세부 정보 제공
  - 각각의 접근을 위한 메소드 존재

### `OnceperRequestFilter`

- 추상 클래스
- 필터가 요청 당 한 번만 실행되어야 하는 경우 확장하여 구성
  - `doFilter()` 메소드 내부에 필터가 이미 실행되었는지의 여부를 결정하는 로직 존재 \
    -> 필터에 사용할 로직을 `doFilterInternal()`에 적어야 함
- 유용한 추가 메소드
  - `shouldNotFilter()`
    - 일부 REST API 경로에 대하여 이 필터를 실행하고 싶지 않을 때 사용
    - 해당 세부 정보 정의 후 조건에 따라 boolean 값 배정 가능
- 예외적인 필터링 시나리오를 적용할때 유용
- `BasicAuthenticationFilter`에서 이용 중

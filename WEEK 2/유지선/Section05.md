# Section 5

## 기본 AuthenticationProvider

### DaoAuthenticationProvider

- Spring Security 기본 인증 제공자
  - 저장 시스템에서 사용자의 세부정보 가져오기
  - 암호 구성
  - 엔드 유저 인증
- 맞춤 인증 논리를 가지고 싶다면 인증 논리 작성 필요 \
  -> `AuthenticationProvider` 정의 필요

### AuthenticationProvider가 여러 개 필요한 경우

- 다양한 접근을 통해 최종 사용자를 인증하는 상황이 요구되는 경우
  - `username`과 `password`를 통한 접근
  - `OAuth 2.0` 인증을 사용한 접근
  - `OTP` 인증을 사용한 접근
- 인증 방법의 개수 만큼 `AuthenticationProvider` 생성

## AuthenticationManager 구성

### `AuthenticationProvider` interface

```Java
public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication) throws AuthenticationException;
    boolean supports(Class<?> authentication);
}
```

- `authenticate(Authentication authentication)`
  - `authentication` : 엔드 유저의 유저 이름과 신임증이 포함된 인증 객체
  - 비즈니스 로직 실행 시 인증이 성공적이었는지에 대한 정보를 가지고 있어야 함 \
    -> 성공 여부에 따라 `ProviderManager`가 다른 `AuthenticationProvider`를 불러올지 판단
- `support()`
  - `AuthentictionProvider`로 인증하고 싶은 인증의 종류를 알려주어야 함
    - 가장 일반적인 인증 방식 : `username` + `password`
    ```Java
    // AbstractUserDetailsAuthenticationProvider.support()
    @Override
    public boolean supports(Class<?> authentication) {
    	return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
    ```
    - `UsernamePasswordAuthenticationToken`형태의 모든인증을 다룰 것이라는 것을 알려줌
- `TestingAuthenticationToken` : `unit test`를 진행할 때 사용 가능

### 자체 `AuthenticationProvider` 생성

```Java
public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();

        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size()>0){
            if (passwordEncoder.matches(pwd, customer.get(0).getPwd())){
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
            } else{
                throw new BadCredentialsException("Invalid password");
            }
        } else{
            throw new BadCredentialsException("No user registered with this details");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
```

- 고객 대상이 데이터베이스에 없을 때
  - `BadCredentialsException("No user registered with this details");`
- 비밀번호가 일치하지 않을 때
  - `BadCredentialsException("Invalid password");`
- `customerRepository`를 통하여 유저 정보를 불러옴 \
  -> `UserDetailsService`를 구현한 객체가 필요 없음 - `UserDetailsService`의 `loadUserByUsername()`가 유저 정보를 가져오는 역할 수행

```Java
// ProviderManager.authenticate(Authentication authentication)
if (result != null) {
    if (this.eraseCredentialsAfterAuthentication && (result instanceof CredentialsContainer)) {
        ((CredentialsContainer) result).eraseCredentials();
    }
    if (parentResult == null) {
        this.eventPublisher.publishAuthenticationSuccess(result);
    }

    return result;
}
```

- **하우스키핑(housekeeping)**
  - `ProviderManager` 속에서 결과가 도출된 이후 인증 정보(비밀번호) 제거

### UserDetailsService 사용 없이 AuthenticationProvider 구현

- `UserDetailsService` 관련 로직이 전혀 필요 없음
  - 유저 상세 정보 검색 로직을 `authentication()` 자체에 작성

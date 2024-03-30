# Section 7

## 인증(Authentication)과 인가(Authorization)의 차이점

### 인증(Authentication)

- 웹 애플리케이션에 접근하려는 유저 식별 \
   -> 인증이 없다면 보안 api에 접근 불가능
- 항상 권한부여보다 먼저 등장 (AuthN)
- 인증을 요구하기 위해서 로그인 세부 정보만을 질문 \
   -> 인증만을 위한 수집
- 인증 실패 시 `401` 에러 코드 반환

### 인가(Authorization)

- 인증이 성공적으로 완료된 이후 진행
  -> 다양한 사용자 권한에 기반하여 다양한 보안 시나리오 설정 가능
- 인증이 진행된 이후 실행 (AuthZ)
  - 인증 없이 권한 부여가 발생하지 않음
- 자격 증명에 대하여 걱정할 필요가 없음
- 권한 부여 실패 시 `403` 에러 코드 반환

## 권한

### 권한의 종류

- 권한 (Authority)
- 역할 (Role)

```Java
public final class SimpleGrantedAuthority implements GrantedAuthority {
private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String role;

	public SimpleGrantedAuthority(String role) {
		Assert.hasText(role, "A granted authority textual representation is required");
		this.role = role;
	}

	@Override
	public String getAuthority() {
		return this.role;
	}
    // 생략
}
```

- `SimpleGrantedAuthority(String role)` (생성자)

  - 특정 엔드 유저에게 권한 혹은 역할 배정
  - 문자열의 형식으로 역할의 이름과 함께 생성

- `getAuthority()`
  - 엔드 유저의 역할이나 권한을 알고 싶을 때 사용
  - `setter` 메소드가 존재하지 않음
    - 엔드 유저에게 권한이 배정된다면 정보를 변경할 수 없음

### 설정된 권한을 확인하는 방법

- `AuthenticationProvider`에서의 `UsernamePasswordAuthenticationToken`의 함수

  ```Java
  // EazyBankAuthenticationProvider
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
              }
              // 생략
          }
      }
  ```

  - `UsernamePasswordAuthenticationToken`의 형식으로 인증 객체를 만들 때 권한 정보를 `SimpleGrantedAuthority` 객체를 만들어 넣음 \
    -> 모든 권한을 수정되지 않는 리스트로 저장

- `UserDetails`에서의 데이터베이스에서 권한을 로딩

  ```Java
  // EazyBankUserDetails
  @Override
  public UserDetails loadByUsername(String username) throws UsernameNotFoundException {
      // 생략
      List<GrantedAuthority> authorities =  null;
      if (customer.size() == 0){
          // 생략
      } else {
          authorities = new ArrayList<>();
          authorities.add(new SingleGrantedAuthrority(customer.get(0).getRole()));
      }
      return new User(username, password, authorities);
  }
  ```

  - User 객체를 생성할 때 권한 정보를 `SimpleGrantedAuthority` 객체를 만들어 넣음

- 어떠한 구조를 사용하더라도 `SimpleGrantedAuthority`를 이용하게 됨

## Spring Security에서의 권한 부여

- 각 유저에게 제한되지 않은 수의 권한 또는 역할 부여 가능 (유연성 제공) \
  -> `Authorities`라는 새로운 테이블 형성 후 유저가 가질 수 있는 권한 종류 정의 가능
  - 고객 테이블과 외래키 연결을 통해 연결 가능

## Spring Security에서 권한 부여를 실행하는 방법

- `requestMatchers()`를 사용하여 특정 엔드포인트에 해당 권한 설정 가능

### `hasAuthority()`

- 특정 권한을 엔드포인트 배열 서비스에 대해 구성 \
  -> 해당 권한을 가진 사용자만 특정 엔드포인트에 접근할 수 있도록 설정

```Java
.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
```

### `hasAnyAuthority()`

- 엔드 유저가 권한들 중 하나라도 가지고 있다면 특정 엔드포인트에 접근 가능
- 특정 엔드포인트에 대하여 여러가지 권한 구성 가능

```Java
.requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT","VIEWBALANCE")
```

### `access()`

- SpEL (Spring Expression Language)의 도움을 받아 복잡한 권한 부여의 규칙 구성 가능
- 논리연산자를 사용하는 복잡한 요구사항과 관련된 권한 설정

### 엔드포인트에 접근에 필요한 권한을 설정하지 않는 경우

- `.authenticated()` 설정 \
  -> 인증이 된 모든 엔드 유저에게 접근 허용

```Java
.requestMatchers("/user").authenticated()
```

## Spring Security에서 권한과 역할의 차이

### 권한 (Authority)

- 사용자가 가질 수 있는 개별 특권
- 엔드 유저가 수행할 수 있는 개별 작업
- 세밀한 방식으로 엑세스 제한 가능
- 대규모 서비스의 경우 매우 많은 작업들에 대한 권한을 제어하기에는 어려움

### 역할 (Role)

- 유저가 여러 활동을 수행할 때 배정
- 일반적으로 권한이나 작업의 그룹
- 접근을 대략적으로 제한
- 권한과 같은 인터페이스로 설정 가능
  - 특정 문자열이 권한인지 역할인지를 구별하기 위하여 `ROLE_` 접두사가 강제됨

## 역할 부여를 통해 권한 부여 강제하기

### 권한 부여 역할 설정 방식

- `hasRole()`
  - 하나의 역할을 하나의 인풋으로 받아들임
  - 해당 역할을 가진 유저만이 특정 엔드포인트에 엑세스 가능
  - `hasAuthority()`와 유사
  ```Java
  .requestMatchers("/myAccount").hasRole("USER")
  ```
- `hasAnyRole()`
  - 주어진 역할 목록 중 해당된다면 엔드포인트 엑세스 가능
  - `hasAnyAuthority()`와 유사
  ```Java
  .requestMatchers("/myBalance").hasAnyRole("USER","ADMIN")
  ```
- `access()`
  - 권한에서 언급되었던과 같은 효과

### 데이터베이스에서의 역할

- 모든 역할은 저장될때 접두사 `ROLE_`을 포함
  - `hasRole()`, `hasAnyRole()`, `access()` 사용시 접두사를 언급하면 안 됨
    - Spring Security 사용 시 내부적으로 접두사 값 추가

# Section 3

## Spring Boot 웹 애플리케이션 메모리에 유저 생성

- 프로덕션 웹 애플리케이션에서의 사용은 추천하지 않음
  - 게시된 코드를 통해 자격 증명을 볼 수 있음

### 접근법 1. `withDefaultPasswordEncoder()` 사용

```Java
public InMemoryUserDetailsManager userDetailsService(){
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("12345")
                .authorities("admin")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("12345")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }
```

- `.withDefaultPsswordEncoder()` : 일반 텍스트로 비밀번호 저장
  - 사용이 권장되지 않음
- `UserDetails`구현체를 생성하여 `InMemoryUserDetailsManager`의 인자로 넘겨 자격증명 생성

```Java
public class InMemoryUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {
    // 생략
    public InMemoryUserDetailsManager(UserDetails... users) {
		for (UserDetails user : users) {
			createUser(user);
		}
	}
    // 생략
}
```

### 접근법 2. `NoOpPasswordEncoder` 사용

```Java
public InMemoryUserDetailsManager userDetailsService(){
        UserDetails admin = User.withUsername("admin")
                .password("12345")
                .authorities("admin")
                .build();
        UserDetails user = User.withUsername("user")
                .password("12345")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
```

- `NoOpPasswordEncoder` : 인코딩을 진행하지 않고 일반 텍스트로 비밀번호 저장

## User 관련 코드

### `UserDetailsService`

```Java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

- `loadUserByUsername()`가 `AuthenticationProvider`에서 호출되어 사용됨
- 저장 시스템에서 유저 이름만으로 로드하는 이유
  - 비밀번호를 불필요하게 네트워크로 전송해서는 안 됨 -> 유저 이름 로드 후 비밀번호를 비교하는 논리 추가

### `UserDetailsManager`

```Java
public interface UserDetailsManager extends UserDetailsService {
    void createUser(UserDetails user);
    void updateUser(UserDetails user);
    void deleteUser(String username);
    void changePassword(String oldPassword, String newPassword);
    boolean userExists(String username);
}
```

- `UserDetailsService`를 상속받은 인터페이스
- 유저 세부정보를 관리하는데 도움됨
- `UserDetailsManager`의 구현체
  - `InMemoryUserDetailsManager`
    - 애플리케이션의 메모리에서 유저 관리
  - `JdbcUserDetailsManager`
    - 데이터베이스를 연결하여 유저 관리
  - `LdapUserDetailsManager`
    - `Ldap` 서버를 사용하여 유저 세부 정보 저장
- 자체 `AuthenticationProvider`을 정의하여 자체 인증 로직 작성 가능

### `UserDetails`

```Java
public interface UserDetails extends Serializable {
    Collection<? extends GrantedAuthority> getAuthorities();
    String getPassword();
    String getUsername();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}
```

- `getAuthorities()` : 엔드 유저의 권한 또는 역할 목록을 보유 -> 권한 부여 또는 역할 기반 엑세스 메커니즘 구현 가능
- `isAccountNonExpired()` : 유저 계정이 만료되었는지 확인
- `isAccountNonLocked()` : 유저 계정이 잠겨있는지 확인
- `isCredentialsNonExpired()` : 유저 자격 증명이 만료되었는지 확인
- `isEnabled()` : 유저 계정의 활성화 여부 확인

### `User`

- `UserDetails`를 상속받아 구현됨
  - `setter`가 없음 : 성공적인 인증을 진행한 이후 권한과 관련된 값을 재지정하는 것을 허용하지 않음

## 인증 관련 코드

### `Authentication`

```Java
public interface Authentication extends Principal, Serializable {
    Collection<? extends GrantedAuthority> getAuthorities();
    Object getCredentials();
    Object getDetails();
    Object getPrincipal();
    boolean isAuthenticated();
    void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

- `isAuthenticated()` : 유저가 성공적으로 인증되었는지 여부를 이해하는 데 사용
- `DaoAuthenticationProvider`에서 유저 인증을 성공하면 `Authentication`을 반환하는 `createSuccessAuthentication` 메소드 사용

```Java
@Override
	protected Authentication createSuccessAuthentication(Object principal, Authentication authentication,
			UserDetails user) {
		// 생략
		return super.createSuccessAuthentication(principal, authentication, user);
	}
```

### `InMemoryUserDetailsManager`

```Java
@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetails user = this.users.get(username.toLowerCase());
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}
		return new User(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(),
				user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
	}
```

- 저장 시스템 (InMemory)에서 유저에 대한 정보의 로딩 담당

> Q. `UserDetailsManager` 에는 여러 유형이 있는데 `DaoAuthenticationProvider`는 어떤 `UserDetailsManager`을 호출해야 하는지 어떻게 알 수 있는가?

`Config`파일에 `Bean`을 생성하여 `InMemoryUserDetailsManager`타입을 사용한다는 것을 지정할 수 있음 \
-> 정의한 `Bean`에 기반하여 인증 정보 공급자 중 하나에게서 호출됨

### `JDBCUserDetailsManager`

```Java
public class JdbcUserDetailsManager extends JdbcDaoImpl implements UserDetailsManager, GroupManager {
  // 생략
}
```

- `GroupManager` : 그룹 생성 후 유저들을 그룹 지정 가능
- `Spring Security` 팀에서 데이터베이스 구조, 테이블 구조, 열 등등 모든 구조를 설꼐하고 이러한 설게로 구현 클래스 속에 모든 것을 코딩해 둠
  - `loadUserByUsername` 메소드 호출 \
    -> 메소드 안에서 쿼리가 생성되고 쿼리에게 유저 이름이 SQL 쿼리 속 변할 수 있는 값으로 보내짐 \
    -> `Spring JDBC` 템플릿의 도움을 받아 구성할 데이터베이스에 대해 쿼리 실행
  ```Java
  // JdbcdaoImpl.java
  public static final String DEF_USERS_BY_USERNAME_QUERY = "select username, password, enabled"
  + "from users"
  + "where username = ?";
  ```

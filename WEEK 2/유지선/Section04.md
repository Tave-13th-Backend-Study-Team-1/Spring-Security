# Section 4

### 엔드 유저 인증 과정 흐름

1. `username` 과 `password` 입력 \
   -> 로그인 버튼 클릭
2. `UserDetailsManager`의 구현 클래스 내부에 있는 `loadUserByUsername` 메소드의 도움으로 저장소에서 유저의 모든 정보를 불러옴
   - `UserDetails` 반환
3. 엔드 유저가 제공한 비밀번호와 데이터베이스에서 불러온 비밀번호 비교
   - `PasswordEncoder`에 따라서 비교 방법이 달라짐
     - `NoOpPasswordEncoder` \
       일반 텍스트로 비교 시도
   - `equals` 메소드 사용

- 비밀번호를 일반 텍스트로 저장하는 경우
  - 관리자가 운영 데이터베이스의 접근 권한을 가짐 \
    -> 모든 고객 또는 엔드 유저의 `username`과 `password` 특정 가능 \
    -> 일반 텍스트로 비밀번호 저장 시 모든 고객 정보 탈취 가능

### `AbstractUserDetailsAuthenticationManager`

```Java
// 일부 생략된 코드
public abstract class AbstractUserDetailsAuthenticationProvider
		implements AuthenticationProvider, InitializingBean, MessageSourceAware {
    @Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 생략
		String username = determineUsername(authentication);
		boolean cacheWasUsed = true;
		UserDetails user = this.userCache.getUserFromCache(username);
		if (user == null) {
			cacheWasUsed = false;
			try {
				user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			}
			catch (UsernameNotFoundException ex) {
				// 생략
			}
            // 생략
		}
		try {
			this.preAuthenticationChecks.check(user);
			additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		}
		catch (AuthenticationException ex) {
			// 생략
		}
		// 생략
	}
}
```

1. `retrieveUser` 메소드를 통해 유저 정보를 불러옴
2. `preAuthenticationChecks` 메소드로 엔드 유저의 계정의 특성 확인
   - 만료되었는지 여부
   - 비활성화 상태인지 여부
3. `additionalAuthenticationChecks` 메소드 호출
   - `DaoAuthenticationProvider` 에서 구현

```Java
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    @Override
	@SuppressWarnings("deprecation")
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		if (authentication.getCredentials() == null) {
			// 생략
		}
		String presentedPassword = authentication.getCredentials().toString();
		if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
			this.logger.debug("Failed to authenticate since password does not match stored value");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
	}
}
```

1. `if (authentication.getCredentials() == null)` 를 통해 인증 객체 내부에 자격 증명이 존재하는지 확인
2. `presentedPassword`로 문자열에 자격증명 할당

- 인증 객체로부터 받는 비밀번호가 엔드 유저가 입력한 비밀번호 \
  -> Spring Security 필터는 `username`과 `password`를 `인증 객체`로 변환

3. `passwordEncoder.matches()` 메소드 호출
   - 비밀번호 비교
   ```Java
   // NoOpPasswordEncoder
   public final class NoOpPasswordEncoder implements PasswordEncoder {
       @Override
   public boolean matches(CharSequence rawPassword, String encodedPassword) {
   	return rawPassword.toString().equals(encodedPassword);
   }
   }
   ```
   - 엔드 유저로부터 수신한 비밀번호와 데이터베이스로부터 불러온 비밀번호의 두 문자열의 일치성 확인
4. 자격증명 일치 여부 확인
   - 두 문자열 일치 : `true` 반환
   - 두 문자열 불일치 : `BadCredentialsException` 예외 반환

## Password Management

### 1. Encoding

- 데이터를 한 형식에서 다른 형식으로 변환하는 과정
- 어떠한 기밀성도 포함하지 않음
- 일반 텍스트 비밀번호를 인코딩 값으로 변경 \
  -> 누구든 인코딩 값을 가져다가 디코딩 과정을 따라할 수 있음 - 아무런 기밀을 포함하지 않음 - 완전히 가역적
- 적합 이용 : MP3 파일 혹은 영상 파일 인코딩
- 업계 준수 유명 인코딩 방법
  - `ASCII`
  - `BASE64`
  - `UNICODE`

### 2. Encryption

- 기밀성을 보장하는 방법
- 암호화 하려고 할 때마다 특정 알고리즘을 따름
  - 암호화 알고리즘에 비밀 키 제공 \
    -> 아무도 이해하지 못하는 방식으로 암호화
- 특정 암호화 값의 일반 텍스트 비밀번호가 무엇인지 알고 싶다면 복호화 필요
- 암호화 알고리즘과 비밀 키는 주로 백엔드 애플리케이션 내부의 기밀 데이터로 관리
- 단점
  - 서버 관리자가 비밀 키와 알고리즘과 같은 변수에 접근 가능
- 적합 이용
  - 데이터베이스 자격 증명
  - Mrs Q 자격 증명
  - SMTP 자격 증명

### 3. Hashing

- 데이터를 수학적 해싱 기능을 활용하여 해시값으로 변경 \
  -> 비밀번호에 해시값을 적용하면 비가역적 \
  -> 누군가에게 해시값을 주면 다시 비밀번호를 알아내는 것은 불가능
- 로그인 과정에서의 검증 방법
  - 해싱 내부 옵션 존재 : 두 개의 해시값
    - 로그인 작업에서 유저가 입력한 비밀번호에 기반해 새로 생성된 해시값
    - 데이터베이스에 저장해둔 엔드 유저의 등록 과정에서 생성된 해시값
  - 두 가지의 해시값으로 비교 진행
- 해시값을 일반 비밀번호로 되돌릴 수 없음 \
  -> 최초의 일반 텍스트 비밀번호를 아는 사람만이 접속 가능
- 해싱 알고리즘
  - `BCrypt`
    - 해싱 알고리즘을 통한 값은 항상 달라지지만 내부에 포함된 해시값은 같음 \
      -> 비교 시 동일한지를 비교 가능

## PasswordEncoder

- `interface`로 두 개의 추상 메소드와 한 개의 기본 메소드 보유

```Java
public interface PasswordEncoder {
    String encode(CharSequence rawPassword);
    boolean matches(CharSequence rawPassword, String encodedPassword);
    default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}
}
```

- `encode(CharSequence rawPassword)`
  - `rawPassword` 또는 일반 텍스트 비밀번호를 해시 문자열 또는 암호화 된 값으로 변환
  - 인코딩 작업이 일어나지 않음
    - 사용하는 `PasswordEncoder`에 따라 해싱 알고리즘 및 해싱 절차가 일어남
- `matches(CharSequence rawPassword, String encodedPassword)`
  - 로그인 작업에서 유저가 입력한 비밀번호와 데이터베이스에 이미 저장된 비밀번호를 비교하기 위해 사용해야 하는 메소드
  - `rawPassword` : 엔드 유저가 로그인 작업에서 입력한 패스워드
  - `encodedPassword` : `loadUserByUsername()`으로 데이터베이스에서 불러온 해시 비밀번호
  - 두 가지 매개변수를 해싱 알고리즘을 사용하여 해시값 유도 \
    -> 해시값의 일치 여부에 따라 `true` / `false` 반환
- `upgradeEncoding(String encodedPassword)`
  - 기본 메소드
  - 언제나 `false`를 반환하는 기본 로직 보유
  - 비밀번호를 두 번 해싱
    - 해킹을 어렵게 만들 수 있음

### NoOpPasswordEncoder

- 해싱, 인코딩, 암호화의 개념이 없음
- 비밀번호를 일반 텍스트로 취급

### StandardPasswordEncoder

- 현재 Spring Security 팀이 지원하지 않음
  - 암호화 알고리즘을 사용하는 레거시 애플리케이션을 지원하고자 구현됨
  - 무작위 솔트값을 사용해 SHA-256 해싱 알고리즘 구현

### Pbkdf2PasswordEncoder

- 5, 6년 전 쯤에 개발된 애플리케이션에서 사용될 수 있음
  - 그 때는 안전하게 여겨짐
- 최근에는 CPU, GPU의 발전과 더불어 안전하지 않음 - 해커가 그래픽 프로세싱 처리 장치 기계와 같이 많은 데이터와 명령을 처리할 수 있는 고성능 GPU 기계를 가지고 있다면 일반 텍스트 비밀번호 탈취 가능
  > **무자별 대입 공격** \
  > 다양한 입력값을 시도해보고 주어진 해시 값의 최초 텍스트 비밀번호 추측 가능

### BCryptPasswordEncoder

- 1999년에 발명된 BCrypt 해싱 알고리즘 사용
  - 많은 연산 능력
  - 광범위한 범위에서 사용
  - 컴퓨터 내부에서 일어나는 최신 발전에 따라 주기적으로 업데이트
- 텍스트 해싱 및 `matches` 메소드 실행은 CPU 연산 요청
  - 밀리초 안에 실행 가능한 코드가 아님
  - 설정 작업량에 따라 CPU 연산량이 매우 늘어남 \
    -> 해커의 무차별 대입 공격이 있더라도 많은 연산 능력 필요 \
    -> 안전하게 사용 가능
- 가장 일반적으로 설정하는 해싱 알고리즘
  - 엔드 유저에게 숫자, 문자로 조합된 8자 이상의 비밀번호를 요청한다면 강력해짐

### SCryptPasswordEncoder

- `BCryptPasswordEncoder`의 고급 버전
  - 많은 연산 능력
  - 메모리 할당 요구

-> 해커의 해킹 시도 시 본인의 RAM 내부의 메모리 제공 필요

### Argon2PasswordEncoder

- 더 최신의 해싱 알고리즘
  - 많은 연산 능력
  - 메모리 할당
  - 다중 스레드 또는 다중 CPU 코어
- 무차별 대입 공격이 사실상 불가능

## 웹 애플리케이션에 `BCryptPasswordEncoder` 구현

```Java
@Bean
public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
}
```

### `PasswordEncoder` 사용 시점

1. 유저의 등록 절차

- 등록 시에 비밀번호를 해싱하여 데이터베이스에 저장 필요

```Java
@RestController
public class LoginController {
    @Autowired
    CustomerRepository customerRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        Customer savedCustomer = null;
        ResponseEntity response = null;
        try {
            String hashPwd = passwordEncoder.encode(customer.getPwd());
            customer.setPwd(hashPwd);
            savedCustomer = customerRepository.save(customer);
            if (savedCustomer.getId() > 0) {
                response = ResponseEntity
                        .status(HttpStatus.CREATED)
                        .body("Given user details are successfully registered");
            }
        } catch (Exception ex) {
            response = ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An exception occured due to " + ex.getMessage());
        }
        return response;
    }
}
```

- `PasswordEncoder` 객체 주입
- `passwordEncoder.encode()`
  - 등록을 위해 인자로 들어온 `customer`의 비밀번호에 해싱 알고리즘 적용

2. 로그인 절차

- `UserDetailsService`를 구현하여 해결 가능
- 비밀번호의 실질적인 비교는 `DaoAuthenticationProvider`에서 일어남
  - `additionalAuthenticationChecks()`
  ```Java
  // additionalAuthenticationChecks()
  if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
    // 생략
  }
  ```
  - 위 if문에서의 `passwordEncoder`는 `BCryptPasswordEncoder`
  ```Java
  // BCryptPasswordEncoder.matches()
  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
  	if (rawPassword == null) {
  		throw new IllegalArgumentException("rawPassword cannot be null");
  	}
  	if (encodedPassword == null || encodedPassword.length() == 0) {
  		this.logger.warn("Empty encoded password");
  		return false;
  	}
  	if (!this.BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
  		this.logger.warn("Encoded password does not look like BCrypt");
  		return false;
  	}
  	return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
  }
  ```
  - `checkpw()`
    - 최초 비밀번호가 동일한 버전 동일한 강도로 해싱 \
      -> 최초 비밀번호에 대해 해시값이 생성되면 메소드는 두 해시 문자열의 해시값이 같은지 확인

### `BCryptPasswordEncoder` 의 해시 패턴

```Java
public BCryptPasswordEncoder(BCryptVersion version, int strength, SecureRandom random) {
		if (strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS || strength > BCrypt.MAX_LOG_ROUNDS)) {
			throw new IllegalArgumentException("Bad strength");
		}
		this.version = version;
		this.strength = (strength == -1) ? 10 : strength;
		this.random = random;
	}
```

- 시작 철자 : 인코더 지원 버전에 따라 달라짐 (`BCryptVersion` - `enum`)
  - `$2a` 버전
    - Spring Security 기본 설정 버전
  - `$2y` 버전
  - `$2b` 버전
- 로그 라운드 수나 작업량 변수 설정 가능
  - `BCryptPasswordEncoder`의 생성자에 인자 넣기
  - `MIN_LONG_ROUNDS` , `MAX_LONG_ROUNDS`
    - 최솟값 : 4
    - 최대값 : 31
- `SecureRandome` 값 설정
  - `솔트`라고 불리는 무작위로 생성된 값을 더해주도록 하는 것

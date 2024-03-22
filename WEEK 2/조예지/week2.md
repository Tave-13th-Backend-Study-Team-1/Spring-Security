# Section 3

### JdbcUserDetailsManager를 이용한 인증 준비단계

1. pom.xml에 아래의 3개 의존성 추가
```java
<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-jdbc</artifactId>
		</dependency>
		<dependency>
			<groupId>com.mysql</groupId>
			<artifactId>mysql-connector-j</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
```

2. application.properties

```java
spring.datasource.url=jdbc:mysql://springsecurity.cjdg8jrihfh3.us-east-2.rds.amazonaws.com/eazybank
spring.datasource.username=admin
spring.datasource.password=MySQLSpringSecurity
spring.jpa.show-sql=true # 콘솔에 있는 모든 sql 표시
spring.jpa.properties.hibernate.format_sql=true # 이해할 수 있도록 sql 검색 표시
```

- 보통은 저런 자격 증명에 대한 정보를 환경변수로 처리한다.

### 맞춤형 UserDetailsService 구현

- 배경: Spring Secuirty가 요구하는 정보와 클라이언트가 필요로 하는 유저에 관한 정보가 다를 때

- Spring Secuirty가 요구사항에 반드시 따를 필요는 없다.

#### JPA Entity와 Repository 생성

- Entity 클래스를 생성해주어 JPA를 활용해 데이터베이스에 접근할 수 있도록 해야한다.
- Repository=데이터베이스 상호작용 관련 로직을 전문적으로 다루는 클래스

```java
@Repository
public interface CustomerRepository extends CrudRepository<Customer,Long> {

    List<Customer> findByEmail(String email); #jpa는 자동으로 비즈니스 처리 로직을 생성
    
}
```
추상 메소드를 기반으로 데이터베이스 내부에 실행될 쿼리가 결정된다.

#### 맞춤형 UserDetailsService 구현
```java
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String userName, password;
        List<GrantedAuthority> authorities;
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size() == 0) {
            throw new UsernameNotFoundException("User details not found for the user : " + username);
        } else{
            userName = customer.get(0).getEmail();
            password = customer.get(0).getPwd();
            authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
        }
        return new User(userName,password,authorities);
    }
   
```

1. username을 통해서 customer 리포지토리에 있는 메소드를 호출하는 것이다.
2. 리포지토리를 통해 가져온 고객 정보 중 userName,password 값은 user 클래스 생성자에게 넘어간다.
3. 역할에 대한 정보를 문자열 값으로 넘긴다.
4. user 클래스 생성자에게 위 정보들을 전달한다.

결론은, 데이터베이스에서 유저 정보를 맞춤형 비즈니스 로직을 통해 반환했다. →  Spring Secuirty프레임워크가 인증에 활용할 수 있도록 하였다. 

# Section4

### Spring Secuirty 에서 비밀번호 검증이 일어나는 과정

- 인증 객체(아이디, 비밀번호) 내부에 사용자가 입력한 자격증명 에 자격증명이 존재하는 지 확인
- 자격증명이 문자열로 저장됨
- NoOpPasswordEncoder의 matches 메소드를 호출하여 사용자가 입력한 비밀번호와 DB에 저장된 비밀번호를 비교

### Encoding

- 데이터를 다른 형식으로 변환하는 과정
- 아무런 기밀성이 보장되지 않음
    - 누구나 인코딩된 문자열을 디코딩하여 원래의 문자열을 알아낼 수 있다
- 음성파일이나 영상을 압축할 때 주로 사용됨

### Encryption

- 일반 텍스트를 암호화하는 특정 알고리을  따르며, 이 과정에서 key 값을 사용한다.
- 비밀 키 값에 따라 암호화 알고리즘은 우리가 이해하지 못하는 형식으로 암호화한다.
- 복호화 과정=암호화의 반대 과정
    - 동일한 암호화 알고리즘&동일한 키를 이용해야 한다!
- 하지만, 알고리즘와 비밀 키 값을 알고있는 관리자의 경우 언제나 복호화할 수 있기 때문에 그리 안전한 방법은 아니다.

### Hashing

- 데이터가 수학적 해싱 기능(=해싱 함수)을 통해 해시값으로 변환된다.
- 이는 비가역적으로, 해시값을 통해 원래의 평문을 예측할 수 없다.
    - 즉 수학적으로 역함수가 성립될 수 없음.
- 비밀번호를 비교하는 과정
    - 사용자가 입력한 비밀번호에 해싱을 적용해
    - DB에 저장되어 있던 해싱된 비밀번호 값과
    - 위에서 생성한 해싱 값을 비교하면 된다.
- 원래의 텍스트 비밀번호를 아는 사람만이 접근할 수 있으므로, 기밀성이 보장됨.
- 장점
    - 비밀번호가 ‘12345’인 평문을 Hashing할 때마다, 매번 다른 해싱 값이 도출된다.
    - 하지만 내부적으로는 같은 값을 가리킨다.
    - 비밀번호가 같은 유저라 하더라도 해싱 값이 다르기 때문에 보안성이 증가한다.

#### 해싱과 passwordencoder로 비밀번호가 인증되는 과정
![PIC01](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/f1e2e196-74ac-48d4-903e-0f40f8fd24d7)

일반 텍스트 형식의 비밀번호가 어디에도 저장/비교되지 않음.

### PasswordEncoder 인터페이스
![PIC02](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/259ca99e-d282-4515-87b2-640e688bbaef)

- 두 개의 추상 메소드와 한 개의 기본 메소드를 포함
- encode
    - 사용자의 등록 절차에 활용됨
    - 사용자가 등록에 사용한 비밀번호를 사용하는 PasswordEncoder 에 기반해 해시 값 또는 암호화된 값으로 변환
- matches
    - 로그인할 때 유저가 입력한 비밀번호와 DB에 저장된 비밀번호의 일치 여부를 판단함
- upgradeEncoding
    - 해커가 우리의 비밀번호를 해킹하고 복호화하여 일반 텍스트 값을 알아내는 과정을 더욱 복잡하게 하기 위한 수단
    - 1번 해싱하는 것만으로 충분하지만, 반환값을 true로 만들어 두번 해싱하는 것도 가능하다.

### PasswordEncoder 구현 클래스

- NoOpPasswordEncoder: 해싱, 암호화, 인코딩의 개념 없이 단순히 텍스트 취급 → 추천하는 방식은 아님.
- StandardPasswordEncoder: 그저 일반 텍스트 비밀번호를 암호화하기 위해 암호화 알고리즘을 사용하는 레거시 애플리케이션을 지원하고자 이 PasswordEncoder를 구현하는 것이기 때문이다.
- pbkdf2PasswordEncoder: 최근에 강력한 CPU, GPU 의 발전으로 암호화된 값을 추측할 수 있기에 현재는 안전하다고 할 수 없다.
___

- BCryptPasswordEncoder:
    - BCrypt 해싱 알고리즘을 사용
    - 해킹을 시도하려면 많은 CPU 연산 능력&많은 시간을 필요로 한다.
    - 사용자에게 **숫자-알파벳-특수문자로 조합 & 8개 이상의 문자열과 같은 유효성 검사를 요구**한다면 가장 효과적이고 안전한 방법이다.
- SCryptPasswordEncoder:
    - 해커의 연산 능력 & RAM 내부의 메모리를 제공해야 하기 때문에, BcryptPasswordEncoder의 고급버전이라고 한다.
- Argon2PasswordEncoder:
    - 연산 능력 & 메모리 & 다중 스레드를 요구하기 때문에 무차별 대입은 거의 불가능하다고 여겨진다.

무차별 대입공격(brute-force attack)

- 쉬운 말로 하면, 그냥 다 넣어보는 것(될 때까지)
- 이때, 통계적으로 많이 쓰이는 문자열 혹은 많이 사용되는 사전상의 단어들을 지속적으로 시도한다.

### BCryptPasswordEncoder

```java
@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

이로써, SpringBoot에 BCrypt 알고리즘을 사용해야 한다고 선언할 수 있다.

#### 유저 등록 절차

```java
@PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        Customer savedCustomer = null;
        ResponseEntity response = null;
        try {
            # 암호화하는 부분
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
```

# Section5

**엔드 유저를 인증하기 위한 AuthenticationProvider(맞춤형인증 논리)를 설계하는 과정에서 다양한요구사항을 만족할 수 있다.**
- 유저이름+비밀번호
- OAUTH
- OTP인증

### AuthenticationProvider 메소드 이해
두 가지 추상 메소드
![PIC03](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/15409e89-5b2a-4597-8fac-4b44b2677955)

- authenticate 메소드
    - 유저의 이름과 비밀번호가 포함된 authentication객체를 입력변수로 받는다.
    - 주어진 **AuthenticationProviders**에 의해 인증 방식을 지원하고 있는지 확인한다.
    - 인증 성공과 관련된 정보를 담고 있어야 한다.
- supports 메소드
    - 어떤 형식으로 로그인을 진행할지 알려주는 메소드이다.
    - 대표적인 형식, 유저 이름 + 비밀번호

### AuthenticationProvider 커스터마이징
```java
@Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size() > 0) {
            if (passwordEncoder.matches(pwd, customer.get(0).getPwd())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        }else {
            throw new BadCredentialsException("No user registered with this details!");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
```

- supports 메소드
    - 유저 이름과 비밀번호로 로그인을 진행하겠다고 선언한
- authenticate 메소드
    1. DB에서  유저 세부 정보를 불러와야 한다.

  `List<Customer> customer = customerRepository.findByEmail(username);`

    1. 비밀번호 비교

  `passwordEncoder.matches(pwd, customer.get(0).getPwd())`

    1. 권한 부여

  `authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));`

    1. 인증 객체 반환=성공 여부 반환

  `return new UsernamePasswordAuthenticationToken(username, pwd, authorities);`
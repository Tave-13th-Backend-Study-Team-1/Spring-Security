## SECTION 3️⃣ (29~)

### 클라우드 내 MySQL 데이터베이스 생성
실습 완료.

### JdbcUserDetailsManager에 따른 데이터베이스 연결과 데이터베이스 내 유저 생성
```sql
create database eazybank;

use eazybank;

CREATE TABLE `users` (
`id` INT NOT NULL AUTO_INCREMENT,
`username` VARCHAR(45) NOT NULL,
`password` VARCHAR(45) NOT NULL,
`enabled` INT NOT NULL,
PRIMARY KEY (`id`));

CREATE TABLE `authorities` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(45) NOT NULL,
  `authority` varchar(45) NOT NULL,
  PRIMARY KEY (`id`));

INSERT IGNORE INTO `users` VALUES (NULL, 'happy', '12345', '1');
INSERT IGNORE INTO `authorities` VALUES (NULL, 'happy', 'write');

CREATE TABLE `customer` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(45) NOT NULL,
  `pwd` varchar(200) NOT NULL,
  `role` varchar(45) NOT NULL,
  PRIMARY KEY (`id`)
);

INSERT INTO `customer` (`email`, `pwd`, `role`)
 VALUES ('johndoe@example.com', '54321', 'admin');
```

### JdbcUserDetailsManager를 사용한 인증
- Dependency 추가
```xml
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

- DataSource
  - JdbcUserDetailsManager에게 데이터베이스를 생성하였으며, 그 정보는 이 데이터 소스에 있다고 알려준다.
- PasswordEncoder 빈이 필요한 이유
  - Spring Security에 비밀번호를 어떻게 저장했는지 알려주어야 한다.
    - 일반 텍스트
    - 암호화 된 비밀번호

### 새로운 테이블을 위한 JPA Entity와 리포지토리 클래스 생성
- @EnableJpaRepositories: 리포지토리가 존재하는 패키지명 입력
- @EntityScan: 웹 어플리케이션 내부에 엔티티들이 존재하는 패키지 정보 입력
- 하지만, 여기서는 엔티티와 레포지토리를 메인 패키지에 생성하였으므로 이 두 개의 주석은 언급하지 않아도 된다.
- @EnableWebSecurity: Spring Boot는 자동으로 dependencies에 따라 보안을 설정해주므로 생략해도 된다.

### 맞춤형 UserDetailsService 구현
EazyBankUserDetails.java
```java
@Service // Spring Security가 이를 인식하게 하기 위해서 빈으로 등록한다
public class EazyBankUserDetails implements UserDetailsService {

    @Autowired
    private CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String userName, password;
        List<GrantedAuthority> authorities;
        List<Customer> customer = customerRepository.findByEmail(username); // 아이디가 곧 이메일
        if (customer.size() == 0) { // 고객이 없으면
            throw new UsernameNotFoundException("User details not found for the user : " + username);
        } else {
            userName = customer.get(0).getEmail();
            password = customer.get(0).getPwd();
            authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
        }
        return new User(userName,password,authorities);
    }

}
```
Spring Security는 두 개의 빈을 발견하게 될 것 이다.
ProjectSecurityConfig.java
```java
@Bean
public UserDetailsService userDetailsService(DataSource dataSource) {
    return new JdbcUserDetailsManager(dataSource);
}
```
하지만, 이 빈을 주석처리하면, 우리의 맞춤 로직을 찾을 것이다.

### 새로운 유저 등록을 허용하는 새 REST API 구축
- 유저 정보를 등록하는 두 가지 방법
  - SQL 스크립트
  - REST API
    - UserDetailsManager 오버라이드
    - 새로운 REST API 개발

LoginController.java
```java
@RestController
public class LoginController {
    @Autowired
    private CustomerRepository customerRepository;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        Customer savedCustomer = null;
        ResponseEntity response = null;
        try {
            savedCustomer = customerRepository.save(customer); // JPA가 자동으로 저장
            if (savedCustomer.getId() > 0) { // 성공
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

- CSRF 에러 해결
  - 다음과 같이 설정하면 CSRF 보안이 해지된다.
ProjectSecurityConfig.java
```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.csrf((csrf) -> csrf.disable())
            .authorizeHttpRequests((requests)->requests
                    .requestMatchers("/myAccount","/myBalance","/myLoans","/myCards").authenticated()
                    .requestMatchers("/notices","/contact","/register").permitAll())
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());
    return http.build();
}
```

Customer.java
```java
    @Id
    @GeneratedValue(strategy= GenerationType.AUTO,generator="native")
    @GenericGenerator(name = "native",strategy = "native") // 새로운 시퀀스 수를 생성하는 일을 데이터베이스에게 맡긴다
    private int id;
    private String email;
    private String pwd;
    private String role;
```
# Section 3

### SpringBoard 웹 애프리케이션 DB 구축

1. 시스템에 MySQL 서버 설치
   - 메모리와 시스템 처리 시간을 아주 많이 잡아 먹음 \
     -> 노트북의 동작이 느려짐
   - 노트북이나 운영체제를 잃거나 데이터가 손상 \
     -> 데이터베이스 내부의 데이터가 모두 사라짐
2. 클라우드에 데이터베이스 설치
   - `AWS`를 사용하여 진행

### AWS에 데이터베이스 설치

1. RDS 섹션 -> 데이터베이스 생성
2. 손쉬운 생성
   - MySQL
   - 프리티어
   - DB Instancen : `springsecurity`
   - password : `mysqlspringsecurity`
3. 공개적인 트래픽에 노출될 수 있도록 설정
   - 데이터베이스 수정 \
     -> `연결` - `추가 구성` - `public access 가능`
4. VPC security groups 선택
   - `인바운드 규칙`을 모든 연결과 허용으로 변경
5. `sqlectron` 으로 연결 테스트 후 SQL 문 작성

```SQL
CREATE database eazybank;
USE eazybank;
```

- 데이터베이스에 원하는대로 표와 열 생성 불가능
  - `JdbcUserDetailsManager` 사용 \
    -> Spring Security에서 원하는 명명 규칙을 따라야 함

```SQL
// Spring Security JDBC
CREATE TABLE `users` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(45) NOT NULL,
    `password` VARCHAR(45) NOT NULL,
    `enabled` INT NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `authorities` (
    `id` int NOT NULL AUTO_INCREMENT,
    `username` varchar(45) NOT NULL,
    `authority` varchar(45) NOT NULL,
    PRIMARY KEY (`id`)
);
```

```SQL
INSERT IGNORE INTO `users` VALUES (NULL, 'happy', '12345', '1');
INSERT IGNORE INTO `authorities` VALUES (NULL, 'happy', 'write');
```

### `JdbcUserDetailsManager`를 활용하기 위한 의존성

```
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-jdbc'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    runtimeOnly 'com.mysql:mysql-connector-j'
}
```

```
// application.properties
spring.datasource.url=jdbc:mysql://springsecurity.example.us-east-1.rds.amazonaws.com/eazybank
spring.datasource.username=admin
spring.datasource.password=MySQLSpringSecurity
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
```

- DevOps 팀은 항상 자격 증명을 `CI/CD` 파이프라인 또는 `Jenkins`와 같은 개발 툴을 이용하여 환경 변수 주입

### JdbcUserDetailsManager 이용

```Java
@Bean
public UserDetailsService userDetailsService(DataSource dataSource){
    return new JdbcUserDetailsManager(dataSource);
}
```

- `UserDetailsService` 중에 `JdbcUserDetailsManager`를 사용한다고 지정

```Java
@Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
```

- `PasswordEncoder` 지정 필요
  - Spring Security 에게 항상 비밀번호를 어떻게 저장하였는지 알려주어야 함
    - 일반 텍스트
    - 암호화 이용
    - 해싱 이용
- 위 예시에서는 `NoOpPasswordEncoder` 이용 \
  -> 비밀번호들이 일반 텍스트로 되어 있으니 인증을 실행할 때도 일반 텍스트로 취급해라

- 데이터베이스 인증의 장점

  - 아무리 많은 유저를 등록하여도 보안이 잘 됨

- 클라이언트의 요청에 따라 프로젝트만의 명명 규칙을 생성해야 한다면 `JdbcUserDetailsManager` 사용 불가능

### `JdbcUserDetailsManager` 없이 보안 사용

```SQL
CREATE TABLE `customer` (
    `id` int NOT NULL AUTO_INCREMENT,
    `email` varchar(45) NOT NULL,
    `pwd` varchar(200) NOT NULL,
    `role` varchar(45) NOT NULL,
    PRIMARY KEY (`id`)
);

INSERT INTO `customer` (`email`, `pwd`, `role`) VALUES ('johndoe@example.com', '54321', 'admin');
```

- `UserDetailsService` 구현

```Java
public class EazyBankUserDetails implements UserDetailsService {
    @Autowired
    CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String userName = null;
        String password = null;

        List<GrantedAuthority> authorities = null;
        List<Customer> customer = customerRepository.findByEmail(username);

        if (customer.size() == 0){
            throw new UsernameNotFoundException("User details not found for the user : " + username);
        } else{
            userName = customer.get(0).getEmail();
            password = customer.get(0).getPwd();
            authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
        }
        return new User(username, password, authorities);
    }
}

```

- `User` 는 `UserDetails`를 상속받은 사용자
- `List<Customer> customer` 에 `username` 으로 `customer` 객체를 가져옴
- return문으로 `User` 객체를 `DaoAuthenticatonProvider` 내부로 넘김 \
  -> 데이터베이스에서 넘긴 비밀번호와 엔드유저로부터 받은 비밀번호 비교
- `SimpleGrantedAuthority`는 `GrantedAuthority` 인터페이스 구현

### UserDetailsService를 두 개 이상 구현

```
No AuthenticationProvider found for org.springframework.security.authentication.UsernamePasswordAuthenticationToken
```

- `AuthenticationManager`에서 모든 사용 가능한 `AuthenticationProvider` 검색 \
  -> `DaoAuthenticationProvider` 에서 인증 진행 불가능 (충돌 발생) - 프로젝트 내부에 `UserDetailsService` 구현이 여러 개

### CSRF

기본적으로 모든 데이터를 변경하는 요청에 대해서는 차단 \
-> 해제 필요

```Java
http.csrf((csrf) -> csrf.disable())
```

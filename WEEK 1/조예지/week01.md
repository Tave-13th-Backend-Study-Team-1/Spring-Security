# Spring Security-Week 1

### spring security 프레임워크를 사용하는 이유

- 보안에만 집중하는 개발자들이 항시 보안에 초점을 두어 안전하게  관리하여 고객들의 요구사항을 반영할 수 있음
- 모든 보안 시나리오를 참고하여 만들어짐
- CSRF 와 CORS 와 같은 보안 취약한 것들을 다룸
- 권한 부여를 통해 역할을 나눌 수 있음
- 다양한 보안 기준을 지원
    - 아이디
    - 비밀번호
    - 토큰(JWT) ..

### Spring Security 내부 흐름

1. 서브렛

- 중개자 역할
- 보통, Apache Tomcat 사용
- 역할: 브라우저로부터 받은 HTTP 메세지를 ServletRequest object로 변환
    - 반대방향 또한 작동
- spirgn 프레임워크가 내부적으로   servlet 을 포함

2. 필터

- 특별한 종류의 서브렛
- sprgin 프레임워크에는 총 10~15개가 포함
- 실질적인 비즈니스 로직이 실행되기 전에 일어났으면 하는 프리로직이나 프리워크를 정의할 수 있다

![pic01](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/7f2d6036-ede9-43ad-bca5-355cb32fb92a)

1.

- 유저는 본인의 자격증명을 백엔드에 전송
- 자체적으로 개발한 필터로 요청을 감시 ← 접근 가능한 경로인지 판단
1. 이미 로그인한 유저인지 체크
2.
- 인증 관리자로 넘김 ← 실질적인 인증 로직을 관리
- 웹 안에 어떤 인증 제공자가 존재하는지 확인
1. 해당 인증 제공자에게 전송
2. `UserDetailsManager / Service` & `Password Encorder`와 같은 인증 제공자로 유저 정보를 비교
3. 비밀번호를 그냥 저장해서는 안됨 → 항상 암호화 또는 해싱이 필요
4. 인증 제공자의 과정이 끝나면 인증 관리자에게 돌아감
5. 필터에게 전송
6. 보안 컨텍스트에 인증 객체를 저장 ← what? 인증이 성공 여부, 세션 ID

7. 엔드 유저(사용자)에게 반환

### 주요 기능 구현체에 대한 설명

![pic02](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/cdcde490-05e5-4855-9a64-61347bfe884a)

- 유저는 필터에 의해 자격 증명을 입력할 의무를 부여 받는다.

- 필터는 인증 객체를 만들어 인증 관리자를 호출한다.

- 모든 가능한 인증 제공자를 시도한다.

- `loadUserbyUsername` `Password Encorder` 와 같은 구현체의 도움으로 유저 정보 일치 여부를 판단한다.

- 인증 관리자가 모든 과정이 성공적이었는지를 판단한 후, 유저에게 그 내용을 전달한다.

### REST API 보호

spring security 와 함께 빌드하고 배포했을 때, 모든 rest api 서비스는 기본적으로 보호된다.

맞춤형 보안?

- 보안 요구사항에 맞게 보안이 필요한 api와 필요하지 않은 api를 구분!
![pic03](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/0cc21249-bcb5-4215-8d3b-8e4fda8c28e4)

`bean`을 통해 자체적인 `SecurityFilterChain`으로 모든 API 를 보호할 수 있음

**들어온 모든 요청은 반드시 인증/증명되어야 한다는 코드**

### 맞춤형 보안 설정 구현

![pic04](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/ea314eeb-0296-49cf-8995-9427ba254c4f)

`.requestMatches` 메소드 호출

보호 o → authenticated

- `/myAccount`, `/myBalance`, `/myLoans`, `/myCards` 들에 대해서 보안 요청
    - `/myAccount/**` 는 기본 경로가 myAccount로 시작되는 모든 경로를 보호한다는 뜻!

보호 x → permitAll

- `/notices`, `/contact` 경로들은 누구나 접근 가능하도록

### 모든 요청을 거절하는 방법
![pic05](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/f6d3c46f-950f-435d-bc08-160ccef4d778)

`.anyRequest().denyAll()`

→ 모든 요청이 거부

어떤 역할, 어떤 자격증명이 사용되든지 관계없이 아무도 접근 불가 → `403에러`반환

왜 자격 증명을 요구하는지?

- 인증
    - 요청을 인증해야 권한 부여가 생성
- 권한 부여
    - 권한 부여 거부 에러 발생(403)

### 모든 요청을 허용하는 방법
![pic06](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/3043071f-7e70-407a-b33a-8af526ebdd88)

.anyRequest().permitAll() 을 통해 아무런 보안 없이 누구에게나 노출됨

### InMemoryUserDetailsManager를 사용한 유저 설정(1)

spring boot 애플리케이션 메모리에 유저를 생성하는 과정

![pic07](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/3b1eb00c-6ac2-4319-ad9f-c1a2573fe7f2)

1. InMemoryUserDetailsManager bean 생성
    1. 이 클래스안에 여러 명의 유저 생성 가능
2. 이름, 비밀번호 그리고 권한 설정입력
    1. 간단한 비밀번호일 경우, `DefaultPasswordEncorder` 를 통해 암호화

   → 하지만 추천 방식은 아님.

3. `.build()`를 통해 유저 생성 정보를 InMemoryUserDetailsManager 생성자에게 전달
    1. `createUser(user);` 를 통해 최종적으로 유저를 생성

### InMemoryUserDetailsManager를 사용한 유저 설정(2)

![pic08](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/7b60d165-2e5c-4830-bbbc-f971ccbd30b3)

User 클래스를 사용하여 UserDetails 를 생성할 때 PasswordEncorder 와 관련된 메소드를 호출하지 않는다.

별도의 `NoOpPasswordEncorder` 메소드를 bean으로 정의한다.

### UserDetailsManager&UserDetailsService

![pic09](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/b83ba50b-659a-4bc5-a0ad-41e8b8aaaf48)


UserDetailsService: 가장 첫 번째 인터페이스

- loadByUsername 메소드 포함
- UserDetails라는 인터페이스를 구현한다.
- **유저 이름**만을 사용하여 유저의 세부 정보를 로드함(이 과정에서 비밀번호는 공유되지 않음→유출될 가능성)
- 유저가 입력한 정보를 기반으로 데이터베이스에 저장된 유저 세부 정보를 불러옴

UserDetailsManager: 다음 인터페이스

- UserDetailsService를 상속
- UserDetails라는 인터페이스를 구현한다.
- 유저의 세부 정보를 관리
    - 유저 생성, 업데이트, 삭제, 비밀번호 변경 및 유저 존재 여부 확인

UserDetails: 모든 클래스 및 인터페이스에서 활용되는 인터페이스

- 이 인터페이스에서 제공하는 클래스의 이름이 `User`

### UserDetails 인터페이스 분석

![pic10](https://github.com/Tave-13th-Backend-Study-Team-1/Spring-Security/assets/81136546/ad73721a-7ef5-4996-88c7-3b613674dc4f)


Authentication - 수많은 userdetail 인터페이스의 속성들을 포함할 필요없이 사용자가 인증된 여부만 포함

1. getAuthorities
- 엔드 유저의 권한 또는 역할 목록을 보유
1. 나머지 메소드
- 유저 계정이 만료되었는지, 잠겨있는지, 활성화되었는지 등을 확인

❗setter 메소드는 존재 x

→ 이 객체 내에 있는 속성들을 읽기만 할 수 있음(getter 로)

→ 값을 재지정하는 것이 불가

### UserDetailsManager 분석

- createUser: 유저에 대한 정보를 기반으로 유저 생성
- deleteUser: 유저 삭제
- updateUser: 유저 업데이트
- userExists: boolean 값 반환
- changePassword: 비밀번호 변경

jdbcUserDetailsManager

ldapUserDetailsManager
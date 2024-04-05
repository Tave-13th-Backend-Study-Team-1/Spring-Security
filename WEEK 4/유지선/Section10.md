# Section 10

## 메소드 레벨 보안

### 메소드 레벨 보안 기능

- `@EnableMethodSecurity`
- 메소드 레벨 보안 기능 활성화
- 애플리케이션의 메인 클래스 또는 구성 클래스 위에 인가 규칙 적용 가능
- 웹이 아닌 애플리케이션에서도 강제로 인가 가능
- REST API 또는 URL이 없는 경우 일부 권한 규칙 강제 가능

### 메소드 레벨 보안 적용 가능한 상황

- 호출 인가
  - 로그인 된 유저 또는 엔드 유저가 이에 따른 권한이나 역할을 구성하는 데 필요한 설정이 있어야 함 \
    -> 보안의 두 번째 레벨 - API와 URL에 인증과 인가를 실시하는 것 외에 메소드 레벨 보안
- 필터링 인가
  - 필터링 조건 또는 권한과 규칙에 의해 어떤 데이터를 유저에게 수락하고 보내고 싶은지 검증 가능

### 메소드 레벨 보안 관련 Annotation

- `@PreAuthorize` (추천)
- `@PostAuthorize` (추천)
- `@Secured`
- `@RoleAllowed`
- `@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)`

## 인가 강제 방법

### `@PreAuthorize`

- 권한에 관한 규칙 또는 보안에 관한 요구 사항을 정의할 때 유저 정보에 따른 보안 관련 요구사항이 충족 되어야지만 해당 메소드가 호출되도록 함
  ```Java
  @PreAuthorize("hasAuthority("VIEWLOANS")")
  @PreAuthorize("hasRole("ADMIN")")
  @PreAuthorize("hasAnyRole("ADMIN", "USER")")
  @PreAuthorize("# username == authentication.principal.username") // SpEL
  ```
  - "# username == authentication.principal.username"
    - ID인 입력 매개변수를 가지고 로그인된 ID와 메소드로 받은 input의 ID가 동일한지 확인
    - 인증 객체 속의 principal을 통해 username 호출 가능

### `@PostAuthorize`

- 메소드의 호출을 멈추지 않고 별도 권한 규칙 없이 실행
- 정의된 권한 규칙을 기반으로 output을 유저에게 다시 돌려보내야 하는지 결정
  ```Java
  @PostAuthorize("returnObject.username == authentication.principal.username")
  @PostAuthorize("hasPermission(returnObject, 'ADMIN')")
  ```

### `PermissionEvaluator` 인터페이스 구현

- `hasPermission()`
  - 복잡한 로직 작성 가능
  - boolean 값을 리턴하여 메소드 호출이 허용되는지 안되는지 이해 가능

```Java
public interface PermissionEvaluator extends AopInfrastructureBean {
    boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission);
    boolean hasPermission(Authentication authentication, Serializble targetId, Object permission);
}
```

- `authentication` : 로그인 된 유저에 대한 정보
- `targetDomainObject` : 엔드 유저에게 리턴하려는 객체 또는 엔드 유저에게서 받는 객체와 같은 객체들을 보낼 수 있음
  - 타겟 종류의 ID가 아니라 객체 자체를 보낼 수 있음
- `permission` : 메소드 내에서 평가

## 애너테이션 적용 원리

- Spring AOP
  - 메소드 호출 이전에 가져와 애너테이션의 도움으로 구성한 모든 권한 보유 관련 규칙 실행 가능

## 메소드 레벨 보안 설정

### `@EnableMethodSecurity` 애너테이션 설정

```Java
@EnableMethodSecurity(prePostEnabled = true, secureEnabled = true, jsr250Enabled = true)
```

- `prePostEnabled` : `@PreAuthroize`와 `@PostAuthorize` 주석 사용 가능
- `secureEnabled` : `@Secure` 사용 가능
- `jsr250Enabled` : `@RoleAlert` 사용 가능

### `@PreAuthorize` 설정

```Java
@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {
	@PreAuthorize("hasRole('USER')")
	List<Loans> findByCustomerIdOrderByStartDtDesc(int customerId);
}
```

- USER 권한을 가지지 않는다면 클라이언트에 에러 반환

### `@PostAuthorize` 설정

```Java
@RestController
public class LoansController {
    // 생략
    @GetMapping("/myLoans")
    @PostAuthorize("hasRole('USER')")
    public List<Loans> getLoanDetails(@RequestParam int id) {
    // 생략
    }
}
```

## 필터링 조건 설정 가능

### `@PreFilter`

- 실제 비즈니스 로직에 작성해둔 요구사항 기반으로 필터링된 정보만을 보낼 수 있음
  ```Java
  @PreFilter("filterObject.contactName != 'Test'")
  ```
  - 로그인 된 유저의 입력만 받는 필터링 진행 가능
- PreFilter 하려는 메소드 입력은 반드시 컬렉션 인터페이스 유형이어야 함

### `@PostFilter`

- 작성한 메소드 객체의 필터링 기준 혹은 권한 기준 시행 가능
- 적용할 객체는 컬렉션 유형이어야 함
  ```Java
  @PostFilter("filterObject.contactName != 'Test'")
  ```
  - contactName에 test이름이 아닌 객체들만 반환

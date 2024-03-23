# SECTION 5️⃣
### 개인적 AuthenticationProviders를 생성해야 하는 이유
- 엔드 유저들 중에 18세 이상의 나이를 가진 사용자들만 시스템에 접근을 허용하거나 허용 국가 목록에 있는 엔드 유저들만 접속을 허용하는 등 요구 사항이 있을 수 있다.
- 이렇듯 맞춤 인증 로직을 작성하고 싶으면 Authentication Providers를 직접 작성해야 한다.

### AuthenticationProvider 메소드의 이해
AuthenticationProvider.java
```java
// 두 가지의 추상 메소드
public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication)
            throws AuthenticationException; // 인증 성공과 관련된 정보를 담고 있어야 한다.
    boolean supports(Class<?> authentication); // 어떤 형식으로 로그인을 진행할지 알려주는 메소드이다.
}
```

OTP는 요구 사항에 기반하여 정의할 수 있는 개별 비즈니스 로직이다.
EazyBankUsernamePwdAuthenticationProvider.java
```java
@Component
public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // 저장 시스템에서부터 유저 세부사항을 로딩하고 비밀번호를 비교하는 것까지 정확하게 정의해야 한다.
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size() > 0) {
            if (passwordEncoder.matches(pwd, customer.get(0).getPwd())) { // 비밀번호 일치 여부
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customer.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(username, pwd, authorities); // 아이디, 비밀번호, 권한을 UsernamePasswordAuthenticationToken에 넣어서 반환한다. 아이디, 비밀번호, 권한을 가지고 있는 인증 객체이다.
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        } else {
            throw new BadCredentialsException("No user registered with this details!");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication)); // Username과 비밀번호로 인증을 진행하겠다고 선언
    }
}
```
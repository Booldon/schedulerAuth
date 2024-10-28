package scheduler.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.server.Cookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import scheduler.auth.dto.CustomUserDetails;
import scheduler.auth.entity.RefreshToken;
import scheduler.auth.service.RefreshTokenService;
import scheduler.auth.util.StringGenerator;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

// Controller를 통한 로그인 로직이아닌 filter를 통하여 login 로직 구현
// UsernamePasswordAuthenticationFilter을 상속 받음
// 상속받은 UsernamePasswordAuthenticationFilter를 확인해 보면 RequestMatcher Post, /login이 보인다.
// -> UsernamePasswordAuthenticationFilter 는 AbstractAuthenticationProcessingFilter 를 상속 받음
// -> successfulAuthentication과 unsuccessfulAuthentication에 대한 로직은 AbstractAuthenticationProcessingFilter의 doFilter에 구현 되어 있음
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    private final RefreshTokenService refreshTokenService;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    public void setUrl(String url) {
        this.setFilterProcessesUrl(url);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 (POST 요청 body부분) username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //출력
        System.out.println("username / password : "+username+" / "+ password);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        CustomUserDetails customUserDetails = (CustomUserDetails) authenticationManager.authenticate(authToken).getPrincipal();
        //token을 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공시 실행 하는 메소드
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        //UserDetailsS
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        System.out.println("auth.getAuthority() : "+ auth.getAuthority());
        String role = auth.getAuthority();

        System.out.println("refreshTokenService.isExist(username) : " + refreshTokenService.isExist(username));

        //refreshToken 생성
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(username, role);

        //jwt 생성
        String token = jwtUtil.createJwt(username, role, refreshToken.getRandomKey(), 15*1000L);
        ResponseCookie responseCookie = jwtUtil.generateTokenCookie(token);
        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
//        response.sendRedirect("http://localhost:3000");

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {

        response.setStatus(401);
    }
}

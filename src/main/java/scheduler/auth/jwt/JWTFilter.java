package scheduler.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import scheduler.auth.dto.CustomUserDetails;
import scheduler.auth.entity.RefreshToken;
import scheduler.auth.entity.User;
import scheduler.auth.service.RefreshTokenService;

import java.io.IOException;
import java.util.Collection;

public class JWTFilter extends OncePerRequestFilter {


    private final JWTUtil jwtUtil;

    private final RefreshTokenService refreshTokenService;

    public JWTFilter(JWTUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        if ("/join".equals(request.getRequestURI()) || "/login".equals(request.getRequestURI())) {
//            filterChain.doFilter(request, response);
//            return;
//        }

        //request에서 Authorization 쿠키를 찾음
        String authorization = null;
        Cookie[] cookies = request.getCookies();

        if(cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Authorization")) {

                    authorization = cookie.getValue();
                }
            }
        }

        System.out.println("Cookie Authorization : " + authorization);

        //Authorization 헤더 검증
        if (authorization == null) {

            System.out.println("token null");
            filterChain.doFilter(request, response); //doFilter로 다음 필터로 넘겨줌

            //조건이 해당되면 메소드 종료
            return;
        }

        //token 추출
        String token = authorization;

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        System.out.println("username : " + username);

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) { //true : JWT토큰 만료

            System.out.println("token expire... searching RefreshToken");

            //RefreshToken 검증
            if(refreshTokenService.isExist(username)) { //RefreshToken이 존재하면
                RefreshToken refreshToken = refreshTokenService.findRefreshToken(username); //DB에서 조회

                if(refreshToken.getLimitTime().getTime() < System.currentTimeMillis()){ //존재하지만, 만료되었을때
                    System.out.println("RefreshToken is expired");

                    filterChain.doFilter(request, response);
                    //조건이 해당 되면 메소드 종료
                    return;
                }

                if(!refreshToken.getRandomKey().equals(jwtUtil.getRandomKey(token))){ //randomkey matching
                    System.out.println("randomkey dosen't matching");

                    filterChain.doFilter(request, response);
                    //조건이 해당 되면 메소드 종료
                    return;
                }

                System.out.println("create JWT By RefreshToken");

                //JWT 생성,교체
                token = jwtUtil.createJwt(refreshToken.getUsername(), refreshToken.getRole(), refreshToken.getRandomKey(),15*1000L);
                ResponseCookie responseCookie = jwtUtil.generateTokenCookie(token);
                response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
                
                //refreshToken 재생성
                //refreshTokenService.createRefreshToken(refreshToken.getUsername(),refreshToken.getRole());
                //if절 종료후 SecurityContext에 담는 로직
            }

            else { //RefreshToken이 존재하지 않으면
                System.out.println("null RefreshToken");
                filterChain.doFilter(request, response);

                return;
            }

        }

        String role = jwtUtil.getRole(token);
        System.out.println("userrole : "+ role);

        //userEntity를 생성하여 값 set
        User userEntity = new User();
        userEntity.setUsername(username);
        userEntity.setEmail("test@test1.com");
        userEntity.setPassword("temppassword"); //임의의 값 지정
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체에 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
        // 사용자 객체에서 권한을 가져옴
        Collection<? extends GrantedAuthority> authorities = customUserDetails.getAuthorities();

        // 각 권한을 출력해보는 예시
        for (GrantedAuthority authority : authorities) {
            System.out.println("customUserDetails.getAuthorities() : " + authority.getAuthority()); // 이때 getAuthority()가 호출됨
        }

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        System.out.println("AuthToken : " + authToken);

        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
        System.out.println("SecurityContextHolder: " + SecurityContextHolder.getContext().getAuthentication());
        System.out.println("SecurityContextHolder Strategy: " + SecurityContextHolder.getContextHolderStrategy());


        filterChain.doFilter(request, response);

    }
}

package scheduler.auth.config;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import scheduler.auth.jwt.JWTUtil;
import scheduler.auth.service.RefreshTokenService;

import java.util.Arrays;

public class CustomLogoutHandler implements LogoutHandler {

    private final RefreshTokenService refreshTokenService;
    private final JWTUtil jwtUtil;

    public CustomLogoutHandler(RefreshTokenService refreshTokenService, JWTUtil jwtUtil) {
        this.refreshTokenService = refreshTokenService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        //request에서 Authorization 쿠키를 찾음
        String authorization = null;
        Cookie[] cookies = request.getCookies();

        if(cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Authorization")) {

                    authorization = cookie.getValue();

                    // 쿠키 만료 설정
                    cookie.setMaxAge(0);
                    cookie.setPath("/"); // 쿠키의 경로가 설정되어 있을 경우 동일하게 설정 필요
                    response.addCookie(cookie); // 만료된 쿠키를 응답에 추가
                }
            }
        }

        if(authorization != null) {
            String token = authorization;

            refreshTokenService.deleteRefreshToken(token);
        }
        System.out.println("XXX logoutHandler XXX");
    }
}

package scheduler.auth.oauth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.server.Cookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import scheduler.auth.dto.CustomOAuth2user;
import scheduler.auth.entity.RefreshToken;
import scheduler.auth.jwt.JWTUtil;
import scheduler.auth.service.RefreshTokenService;
import scheduler.auth.util.StringGenerator;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    private final RefreshTokenService refreshTokenService;

    public CustomOAuth2SuccessHandler(JWTUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //OAuth2User
        CustomOAuth2user customUserDetails = (CustomOAuth2user) authentication.getPrincipal();

        String username = customUserDetails.getUsername();
        System.out.println("++authentication.authentication++" + authentication);
        System.out.println("++authentication.username++" + username);


        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("++authentication.getAuthorities()++" + authentication.getAuthorities());
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();


        System.out.println("refreshTokenService.isExist(username) : " + refreshTokenService.isExist(username));
        //refreshToken 생성
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(username, role);

        String token = jwtUtil.createJwt(username, role, refreshToken.getRandomKey(), 60*60*60*60L);

//        response.addCookie(createCookie("Authorization", token));
        ResponseCookie responseCookie = generateTokenCookie(token);
        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
        response.sendRedirect("http://localhost:3000/");

    }

    private ResponseCookie generateTokenCookie(String token) {
        return ResponseCookie.from("Authorization",token)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite(Cookie.SameSite.NONE.attributeValue())
                .build();
    }
}

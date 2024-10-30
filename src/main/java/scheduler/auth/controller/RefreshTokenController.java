package scheduler.auth.controller;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import scheduler.auth.dto.UserDTO;
import scheduler.auth.entity.RefreshToken;
import scheduler.auth.exception.TokenStillValidException;
import scheduler.auth.exception.UnauthorizedException;
import scheduler.auth.jwt.JWTUtil;
import scheduler.auth.service.RefreshTokenService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;

    @PostMapping("/refresh")
    public ResponseEntity<String> refreshAccessToken(@CookieValue(value = "Authorization", required = false) String accessToken, HttpServletResponse response) {
        try {
            String newAccessToken = refreshTokenService.refreshAccessToken(accessToken);
            ResponseCookie responseCookie = ResponseCookie.from("Authorization", newAccessToken)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());

            return ResponseEntity.ok("Access token refreshed");
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        } catch (TokenStillValidException e) {
            return ResponseEntity.ok(e.getMessage());
        }
    }

    @DeleteMapping("/deleteUser")
    public ResponseEntity<String> deleteRefreshToken(@CookieValue(value = "Authorization", required = false) String accessToken, HttpServletResponse response, HttpServletRequest request) {

        refreshTokenService.deleteRefreshToken(accessToken);
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Authorization")) {
                    // 쿠키 만료 설정
                    cookie.setMaxAge(0);
                    cookie.setPath("/"); // 쿠키의 경로가 설정되어 있을 경우 동일하게 설정 필요
                    response.addCookie(cookie); // 만료된 쿠키를 응답에 추가
                }
            }
        }

        return ResponseEntity.ok("delete user's refreshToken complete");
    }
}

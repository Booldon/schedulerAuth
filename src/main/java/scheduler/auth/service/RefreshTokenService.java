package scheduler.auth.service;

import org.springframework.stereotype.Service;
import scheduler.auth.entity.RefreshToken;
import scheduler.auth.exception.TokenStillValidException;
import scheduler.auth.exception.UnauthorizedException;
import scheduler.auth.jwt.JWTUtil;
import scheduler.auth.repository.RefreshTokenRepository;
import scheduler.auth.util.StringGenerator;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTUtil jwtUtil;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JWTUtil jwtUtil) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
    }

    public RefreshToken createRefreshToken(String username, String role) {

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUsername(username);
        refreshToken.setRole(role);
        refreshToken.setLimitTime();
        refreshToken.setRandomKey(StringGenerator.generateRandomString(32));

        refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    public RefreshToken findRefreshToken(String username) {
        Optional<RefreshToken> refreshTokenOptional = refreshTokenRepository.findById(username);
        return refreshTokenOptional.orElse(null);
    }

    public Boolean isExist(String username) { // 존재하는가?
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findById(username);
        return refreshToken.isPresent();
    }

    public void deleteRefreshToken(String randomKey) {
        // findById를 사용하여 Optional<RefreshToken> 반환
        Optional<RefreshToken> refreshTokenOptional = refreshTokenRepository.findByRandomKey(randomKey);
        // 존재하는 경우, 해당 RefreshToken 삭제
        refreshTokenOptional.ifPresent(refreshToken -> refreshTokenRepository.delete(refreshToken));
    }

    public String refreshAccessToken(String accessToken) {

        if (accessToken == null) {
            throw new UnauthorizedException("AccessToken 쿠키가 존재하지 않습니다.");
        }

        if (jwtUtil.isExpired(accessToken)) {
            String username = jwtUtil.getUsername(accessToken);
            RefreshToken refreshToken = findRefreshToken(username);

            System.out.println("refreshToken : " + refreshToken);

            if (refreshToken == null || !refreshToken.validateRamdomKey(jwtUtil.getRandomKey(accessToken))) {
                throw new UnauthorizedException("RefreshToken 또는 JWT 검증 실패");
            }

            refreshToken = createRefreshToken(refreshToken.getUsername(), refreshToken.getRole());
            return jwtUtil.createJwt(refreshToken.getUsername(), refreshToken.getRole(), refreshToken.getRandomKey(), 150 * 1000L);
        }

        throw new TokenStillValidException("Access token still valid");
    }
}

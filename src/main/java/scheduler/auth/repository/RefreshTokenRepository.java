package scheduler.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import scheduler.auth.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    //username을 받아 해당 Refresh 토큰을 찾는다.
    @Override
    RefreshToken getReferenceById(String string);
}

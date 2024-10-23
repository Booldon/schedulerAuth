package scheduler.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import scheduler.auth.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);

    Boolean existsByUsername(String username);

    Optional<User> findByEmail(String email);
}

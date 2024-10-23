package scheduler.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "users")
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    private String role;

    // 생성자
    public User(String email, String password, String name) {
        this.email = email;
        this.password = password;
        this.username = name;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();

        if(email.equals("jbg9409@gmail.com")) {
            this.role = "ROLE_ADMIN";
        }
        else {
            this.role = "ROLE_USER";
        }
    }

    @PreUpdate
    private void preUpdateDate() {
        this.updatedAt = LocalDateTime.now();
    }
}

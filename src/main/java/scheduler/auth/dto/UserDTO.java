package scheduler.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {

    private String role;
    private String username;
    private String password;
    private String email;
}

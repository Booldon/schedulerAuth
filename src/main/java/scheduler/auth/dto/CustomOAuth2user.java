package scheduler.auth.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class CustomOAuth2user implements OAuth2User {

    private final UserDTO userDTO;

    public CustomOAuth2user(UserDTO userDTO) {
        this.userDTO = userDTO;
    }

    @Override
    public Map<String, Object> getAttributes() { // naver나 google등 소셜로그인에서 반환하는 response의 attribute 타입이 모두 달라 사용X

        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userDTO.getRole();
            }
        });


        return null;
    }

    @Override
    public String getName() {

        return userDTO.getUsername();
    }

    public String getUsername() {

        return userDTO.getUsername();
    }

}

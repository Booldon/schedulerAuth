package scheduler.auth.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import scheduler.auth.dto.UserDTO;
import scheduler.auth.entity.User;
import scheduler.auth.repository.UserRepository;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(UserDTO userDTO) {

        String username = userDTO.getUsername();
        String password = bCryptPasswordEncoder.encode(userDTO.getPassword());

        Boolean isExist = userRepository.existsByUsername(username);

        if(isExist) {
            System.out.println("이미 존재 하는 유저입니다.");
            return;
        }
        // email, password, name순
        User newUser = new User(userDTO.getEmail(), password, username);

        userRepository.save(newUser);
    }
}

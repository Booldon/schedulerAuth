package scheduler.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import scheduler.auth.dto.UserDTO;
import scheduler.auth.entity.User;
import scheduler.auth.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

//    public User createUser(UserDTO userDTO) {
//
//        log.info("user : {}",userDTO);
//        log.info("email : {}",userDTO.getEmail());
//        log.info("password : {}",userDTO.getPassword());
//        log.info("name : {}",userDTO.getUsername());
//
//        // email, password, name순
//        User newUser = new User(userDTO.getEmail(), userDTO.getPassword(), userDTO.getUsername());
//        return userRepository.save(newUser);
//    }

    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public User updateUser(Long id, UserDTO userDetails) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setUsername(userDetails.getUsername());
        user.setEmail(userDetails.getEmail());
        user.setPassword(userDetails.getPassword());
        user.setUpdatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userRepository.delete(user);
    }


}

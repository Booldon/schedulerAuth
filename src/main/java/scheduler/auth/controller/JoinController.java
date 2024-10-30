package scheduler.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import scheduler.auth.dto.UserDTO;
import scheduler.auth.entity.User;
import scheduler.auth.service.JoinService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public ResponseEntity<String> joinProcess(@RequestBody UserDTO userDTO) {

         User user = joinService.joinProcess(userDTO);

        return ResponseEntity.ok().body(user.getUsername() + "join complete");
    }
}

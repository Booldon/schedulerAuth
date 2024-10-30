package scheduler.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import scheduler.auth.dto.UserDTO;
import scheduler.auth.service.JoinService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody UserDTO userDTO) {

        joinService.joinProcess(userDTO);

        return "ok";
    }
}

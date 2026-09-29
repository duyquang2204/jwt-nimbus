package vn.iotstar.jwt.controller;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import vn.iotstar.jwt.dto.UserResponse;
import vn.iotstar.jwt.repository.AppUserRepository;

@RestController
@RequestMapping("/users")
public class UserController {

    private final AppUserRepository userRepository;

    public UserController(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/me")
    public Map<String, String> currentUser(
            @AuthenticationPrincipal UserDetails user) {
        return Map.of("email", user.getUsername());
    }

    @GetMapping
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
            .stream()
            .map(UserResponse::from)
            .toList();
    }
}
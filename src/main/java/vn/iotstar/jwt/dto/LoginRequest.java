package vn.iotstar.jwt.dto;

public record LoginRequest(
    String email,
    String password
) {
}
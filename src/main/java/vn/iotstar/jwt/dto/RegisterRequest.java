package vn.iotstar.jwt.dto;

public record RegisterRequest(
    String email,
    String password,
    String fullName
) {
}
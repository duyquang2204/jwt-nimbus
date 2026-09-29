package vn.iotstar.jwt.dto;

public record LoginResponse(
    String token,
    long expiresIn
) {
}
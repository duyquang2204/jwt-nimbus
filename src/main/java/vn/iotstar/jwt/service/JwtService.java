package vn.iotstar.jwt.service;

import java.util.Base64;
import java.util.Date;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JwtService {

    @Value("${security.jwt.secret-base64}")
    private String secretBase64;

    @Value("${security.jwt.expiration-ms}")
    private long expirationMs;

    private byte[] getSecretKey() {
        byte[] key = Base64.getDecoder().decode(secretBase64);

        if (key.length < 32) {
            throw new IllegalStateException(
                "JWT secret phải có tối thiểu 32 bytes khi dùng HS256"
            );
        }

        return key;
    }

    public String generateToken(UserDetails user) throws Exception {
        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject(user.getUsername())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusMillis(expirationMs)))
            .build();

        SignedJWT jwt = new SignedJWT(
            new JWSHeader(JWSAlgorithm.HS256),
            claims
        );

        jwt.sign(new MACSigner(getSecretKey()));

        return jwt.serialize();
    }

    public String verifyAndGetSubject(String token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);

        if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new Exception("Thuật toán JWT không hợp lệ");
        }

        boolean signatureIsValid =
            jwt.verify(new MACVerifier(getSecretKey()));

        if (!signatureIsValid) {
            throw new Exception("Chữ ký JWT không hợp lệ");
        }

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        Date expiration = claims.getExpirationTime();

        if (expiration == null || !expiration.after(new Date())) {
            throw new Exception("JWT đã hết hạn hoặc không có thời hạn");
        }

        return claims.getSubject();
    }
}
package com.luisfelipemunoz.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "1EF8499917BA3030018B7E410AB68730BFAC80842E3AD2BD72AF9E18587356F91AAB58BE1C7657E10AD70EB365BBF1FD17A511DC9738E2B87CCD70653AF166BD160FF6FAE1CF046C6F8F10A58CDB5D7B33A9D9FA5D64EC4A2B771F365186F83D821AC6757F032EECD42597AA5225C0002BB4A19A47BF026BED15DAF1F6409726";
    public String extractUsername(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jwt) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

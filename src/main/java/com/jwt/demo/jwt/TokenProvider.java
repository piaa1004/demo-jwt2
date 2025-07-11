package com.jwt.demo.jwt;

import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.jwt.demo.entities.RefreshToken;
import com.jwt.demo.repository.RefreshTokenRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

//import com.jwt.demo.User;
import org.springframework.security.core.userdetails.User;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {

	// auth : 사용자 정의 클레임 (custom claim)
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long accessTokenValidityInMilliseconds;
    private final long refreshTokenValidityInMilliseconds;
    private Key key;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long accessTokenValidityInSeconds,
            @Value("${jwt.refreshtoken-validity-in-seconds}") long refreshTokenValidityInSeconds) {
        this.secret = secret;
        this.accessTokenValidityInMilliseconds = accessTokenValidityInSeconds * 1000;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInSeconds * 1000;
    }
    
    // 빈이 생성되고 주입을 받은 후에 secret값을 Base64 Decode해서 key 변수에 할당하기 위해
    @Override
    public void afterPropertiesSet() {
    	char x; // sign bit 가진다 또는 안 가진다.
    	// base64로 인코딩된 secret를 바이트 배열로 변환
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        // SignatureAlgorithm.HS512[HMAC-SHA512] 알고리즘에 맞는 
        // 적절한 대칭키 javax.crypto.SecretKey 생성
        // : HMAC-SHA는 대칭키[암호화 키가 아님. 단지 서명 생성/인증을 위한 키]를 사용함
        // : SHA512는 해시 함수
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(Authentication authentication, boolean isAccessToken) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // 토큰의 expire 시간을 설정
        // Returns the number of milliseconds
        // since January 1, 1970, 00:00:00 GMTrepresented by this Date object.
        long now = (new Date()).getTime();        								   
        
        long date = 0;
        if (isAccessToken)
        	date = now + this.accessTokenValidityInMilliseconds;
        else
        	date = now + this.refreshTokenValidityInMilliseconds;
        
        Date validity = new Date(date);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities) // 정보 저장
                .signWith(key, SignatureAlgorithm.HS512) // 사용할 암호화 알고리즘과 , signature 에 들어갈 secret값 세팅
                .setExpiration(validity) 
                .compact();
        
//        return Jwts.builder()
//        	    .setHeaderParam("typ", "JWT")
//        	    .setIssuer("auth.example.com")
//        	    .setSubject(authentication.getName())
//        	    .setIssuedAt(new Date())
//        	    .setExpiration(validity)
//        	    .setId(UUID.randomUUID().toString())
//        	    .claim("auth", authorities)
//        	    .claim("email", user.getEmail())
//        	    .claim("nickname", user.getNickname())
//        	    .signWith(key, SignatureAlgorithm.HS512)
//        	    .compact();
    }
    
    public String createAndPersistRefreshTokenForUser(Authentication authentication) {
    	String refreshToken = this.createToken(authentication, false);
        
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.refreshTokenValidityInMilliseconds);
        Instant instant = validity.toInstant();
        
        LocalDateTime localDateTime = instant.atZone(ZoneId.systemDefault())
        		.toLocalDateTime();
        
    	String username = authentication.getName();
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUsername(username);
        refreshTokenEntity.setToken(refreshToken);
        refreshTokenEntity.setExpiryDate(localDateTime); 
        refreshTokenRepository.save(refreshTokenEntity);

        return refreshToken;
    }
    
    // 토큰으로 클레임을 만들고 이를 이용해 User 객체를 만들어서 최종적으로 authentication 객체를 리턴
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        //User(Long, String, String, String, boolean, Set<Authority>)
        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
    
    /**
     * 토큰에서 사용자 이름(username)을 추출하는 메서드
     */
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject(); // subject로 저장된 사용자 이름 반환
    }

    /**
     * 토큰에서 권한 목록(authorities)을 추출하는 메서드
     */
    public Collection<? extends GrantedAuthority> getAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // AUTHORITIES_KEY의 값을 기반으로 권한 목록을 생성하여 반환
        return Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }


    // 토큰의 유효성 검증을 수행
    public boolean validateToken(String token) {
        try {
        	
            Jwts.parserBuilder()
            	.setSigningKey(key)
            	.build()
            	.parseClaimsJws(token);
            
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}


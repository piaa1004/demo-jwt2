package com.jwt.demo.service;

import java.time.LocalDateTime;
import java.util.Optional;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import io.jsonwebtoken.io.Decoders;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;

import com.jwt.demo.controller.RefreshTokenRequest;
import com.jwt.demo.controller.TokenResponse;
import com.jwt.demo.dto.LoginDto;
import com.jwt.demo.dto.TokenDto;
import com.jwt.demo.entities.RefreshToken;
import com.jwt.demo.jwt.JwtAuthenticationFilter;
import com.jwt.demo.jwt.TokenProvider;
import com.jwt.demo.repository.RefreshTokenRepository;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {
	
	private final TokenProvider tokenProvider;
    @Autowired
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;	
	
	public Optional<TokenResponse> makeTokens(LoginDto loginDto) {
		log.info("makeTokens");
    	
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        /*
         makeTokens를 호출한 컨트롤러 메서드는 Spring MVC가 HTTP 요청을 처리하기 위해 호출됨.
         즉, 현재 스레드는 HTTP 요청-응답 처리 스레드임.
		 따라서 이 흐름 내에서 SecurityContextHolder.getContext()를 호출하면,
		 내부적으로 ThreadLocal 기반 SecurityContext가 자동 생성됨
         */
        // 아래 코드로 인해 DaoAuthenticationProvider가 loadUserByUsername를 호출
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        /*
         authenticationManager.authenticate(...)가 하는 일은?
		 내부적으로 다음과 같은 작업들이 수행:
		 1. 적절한 AuthenticationProvider 선택
		 2. 보통 DaoAuthenticationProvider
         3. 내부적으로 UserDetailsService.loadUserByUsername(...) 호출
		 4. DB에서 사용자 정보 조회
         5. PasswordEncoder.matches(raw, encoded) 호출
		 6. 비밀번호 일치 시 Authenticated UsernamePasswordAuthenticationToken 반환
		 # 즉, 위 하나의 코드 라인으로 로그인 인증 절차 전체를 수행하는 것
         */
        log.info("username=" + authentication.getName());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = tokenProvider.createToken(authentication, true);
        String refreshToken = tokenProvider.createAndPersistRefreshTokenForUser(authentication);
        
        TokenResponse tokenResponse = new TokenResponse(accessToken,
        		refreshToken);
        
        Optional<TokenResponse> optTokenResponse = 
        		Optional.ofNullable(tokenResponse);        
        
        return optTokenResponse;        
	}
	
	@Transactional
	public Optional<TokenDto> makeNewAccessToken(RefreshTokenRequest refreshTokenRequest,
    		Authentication authentication) {
		String refreshTokenValue = refreshTokenRequest.getRefreshToken();		
    	
    	log.info("refreshToken from user. token value=" + refreshTokenValue);
    	
        RefreshToken validRefreshToken = 
        		refreshTokenRepository.findById(refreshTokenValue)
                .orElseThrow(() -> new IllegalStateException("Invalid refresh token"));

        TokenDto tokenDto = null;
        Optional<TokenDto> optTokenDto = null;
        if (isTokenExpired(validRefreshToken)) {
            refreshTokenRepository.delete(validRefreshToken);
            optTokenDto = Optional.ofNullable(tokenDto);
            return optTokenDto;
        }
        
        log.info("refreshToken from database. token value=" + validRefreshToken.getToken());
        
        String accessToken = tokenProvider.createToken(authentication, true);
        
        tokenDto = new TokenDto(accessToken);
        optTokenDto = Optional.ofNullable(tokenDto);
        return optTokenDto;
        
	}
	
	public boolean isTokenExpired(RefreshToken refreshToken) {
        return refreshToken.getExpiryDate().isBefore(LocalDateTime.now());
    }
	
}

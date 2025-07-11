package com.jwt.demo.controller;

import java.util.Collection;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


import com.jwt.demo.dto.LoginDto;
import com.jwt.demo.dto.TokenDto;
import com.jwt.demo.entities.RefreshToken;
import com.jwt.demo.jwt.JwtAuthenticationFilter;
import com.jwt.demo.jwt.TokenProvider;
import com.jwt.demo.repository.RefreshTokenRepository;
import com.jwt.demo.service.AuthenticationService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {
   
    private final AuthenticationService authenticationService;
    private final TokenProvider tokenProvider;
    
    @PostMapping("/login") // login
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginDto loginDto) {

    	Optional<TokenResponse> optTokenResponse = 
    			authenticationService.makeTokens(loginDto);
    	
    	HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtAuthenticationFilter.AUTHORIZATION_HEADER, 
        		"Bearer " + optTokenResponse.get().getAccessToken());
        
        ResponseEntity<TokenResponse> ret = ResponseEntity
        	    .ok()
        	    .headers(httpHeaders)
        	    .body(optTokenResponse.get());
        
        return ret;
    } 
    
    @PostMapping("/refresh-accesstoken")
    public ResponseEntity<?> refreshToken(@RequestBody 
    		RefreshTokenRequest refreshTokenRequest,
    		Authentication authentication) {    	
        
        try {        	
        	// Authentication 객체는 null이기 때문에 리프레시 토큰으로 인증 재구성
            if (authentication == null || !authentication.isAuthenticated()) {
                authentication = rebuildAuthenticationFromToken(refreshTokenRequest.getRefreshToken());
                if (authentication == null) {
                    return ResponseEntity.badRequest().body("Invalid refresh token.");
                }
                // SecurityContext에 Authentication 설정
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        	
        	Optional<TokenDto> tokenDto = 
        			authenticationService.makeNewAccessToken(
        					refreshTokenRequest, authentication);
        	
        	if (!tokenDto.isEmpty()) {
        		HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.add(JwtAuthenticationFilter.AUTHORIZATION_HEADER, "Bearer " + tokenDto.get().getToken());
                
                AccessTokenResponse atr = AccessTokenResponse.builder()
                		.accessToken(tokenDto.get().getToken())
                		.build();
                
                ResponseEntity<AccessTokenResponse> ret = ResponseEntity
                	    .status(HttpStatus.OK)
                	    .headers(httpHeaders)
                	    .body(atr);

                return ret;
                
        	} else {
        		// 다시 login 해서, access token과 refresh token을 발급받아야 함.
        		return ResponseEntity.badRequest().body("Refresh token expired. Please login again.");
        	}            
            
        } catch (Exception e) {
            // 에러 처리 (예외 메시지 반환 등)
            return ResponseEntity.badRequest().body(e.getMessage());
        }        
    }
    
    // 리프레시 토큰을 기반으로 Authentication 객체를 재구성하는 메서드
    private Authentication rebuildAuthenticationFromToken(String refreshToken) {
        if (tokenProvider.validateToken(refreshToken)) {
            String username = tokenProvider.getUsernameFromToken(refreshToken);
            Collection<? extends GrantedAuthority> authorities = tokenProvider.getAuthoritiesFromToken(refreshToken);
            return new UsernamePasswordAuthenticationToken(username, null, authorities);
        }
        return null;  // 토큰이 유효하지 않은 경우 null 반환
    }
    
}
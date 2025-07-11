package com.jwt.demo.jwt;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    	http.cors(cors -> cors.disable()); // 단지 테스트용 코드이므로
    	http.csrf(csrf -> csrf.disable());
    	
    	http.exceptionHandling(
    			e -> e.authenticationEntryPoint(jwtAuthenticationEntryPoint)
    			.accessDeniedHandler(jwtAccessDeniedHandler));
    	
    	// 이 설정은 주로 JWT나 OAuth2 토큰 기반 인증과 같이 서버 측 세션 관리가 필요 없는 경우에 사용.
    	// SessionCreationPolicy.STATELESS의 의미
    	// 	* 상태 비저장 (STATELESS)으로 설정하면, 서버가 사용자의 상태 정보를 세션에 저장하지 않음.
    	//  * 매 요청마다 인증 정보가 클라이언트(주로 토큰)를 통해 제공되어야 하며, 서버는 세션을 생성하거나 유지하지 않음.
    	// 동작 방식
    	// SessionCreationPolicy.STATELESS 설정 시 서버는 다음과 같이 동작:
    	//  1. 세션을 생성하지 않음: 인증을 위해 매 Request마다 클라이언트가 인증 Credential(예: JWT 토큰)을 제공해야함.
    	//  2. SecurityContext는 매 Request 마다 초기화: 서버는 세션에 SecurityContext를 저장하지 않으며, 
    	//     Request가 끝나면 Authentication 정보를 제거함.
    	http.sessionManagement(
    			sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    	
    	http.authorizeHttpRequests(auth -> auth
    		    .requestMatchers("/api/login").permitAll() // 로그인 api
    		    .requestMatchers("/api/refresh-accesstoken").permitAll()
    		    .requestMatchers("/api/signup").permitAll() // 회원가입 api
    		    .anyRequest().authenticated()
    		);

    	http.addFilterBefore(new JwtAuthenticationFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
    	
        return http.build();
    }
    
}
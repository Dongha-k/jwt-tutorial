package me.dongha.jwttutorial.config;

import me.dongha.jwttutorial.jwt.JwtAccessDeniedHanler;
import me.dongha.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import me.dongha.jwttutorial.jwt.JwtSecurityConfig;
import me.dongha.jwttutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHanler jwtAccessDeniedHanler;


    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHanler jwtAccessDeniedHanler
    ){
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHanler = jwtAccessDeniedHanler;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web){
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**" // h2 콘솔 하위의 모든 요청과
                        ,"/favicon.ico" // 파비콘 관련 요청에 대한 접근을 허용
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHanler)

                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세선 사용 x

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll() // 토큰을 받기위한 로그인 API
                .antMatchers("/api/signup").permitAll() // 회원가입을 위한 API는 둘다 토큰이 없는 상태에서 요청이 들어오기 때문에 모두 permitAll 설정
                .anyRequest().authenticated() // 위에 url을 제외한 나머지 모든 요청은 모두 토큰값을 가지고 인증을 받아야한다.
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}

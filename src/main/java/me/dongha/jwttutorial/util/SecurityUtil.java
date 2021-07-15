package me.dongha.jwttutorial.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {
    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil(){
    }

    public static Optional<String> getCurrentUserName(){ // Security Context의 Authentication 객체를 이용해 username을 리턴
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // 필터에서 저장된걸 꺼냄
        if(authentication == null){
            logger.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }
        String username = null;
        if(authentication.getPrincipal() instanceof UserDetails){
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            username = springSecurityUser.getUsername();
        } else if(authentication.getPrincipal() instanceof String){
            username = (String) authentication.getPrincipal();
        }
        return Optional.ofNullable(username);
    }
}

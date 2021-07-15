package me.dongha.jwttutorial.service;

import me.dongha.jwttutorial.dto.UserDto;
import me.dongha.jwttutorial.entity.Authority;
import me.dongha.jwttutorial.entity.User;
import me.dongha.jwttutorial.repository.UserRepository;
import me.dongha.jwttutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(UserDto userDto){
        if(userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null){
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();
        return userRepository.save(user);
    }


    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username){ // username을 기준으로 정보를 가져옴
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities(){ // SecurityContext에 저장된 username의 정보를 가져옴
        return SecurityUtil.getCurrentUserName().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}

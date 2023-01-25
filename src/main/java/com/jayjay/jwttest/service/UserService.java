package com.jayjay.jwttest.service;


import com.jayjay.jwttest.dto.UserDto;
import com.jayjay.jwttest.entity.Authority;
import com.jayjay.jwttest.entity.User;
import com.jayjay.jwttest.repository.UserRepository;
import com.jayjay.jwttest.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    // username 이 DB에 존재하지 않으면 Authority 와 User 정보를 생성해서
    // UserRepository의 save 메소드를 통해 DB에 정보를 저장한다.
    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // signup 메소드를 통해 가입한 회원은 ROLE_USER를 가지고 있고
        // admin 계정은 ADMIN_USER , ROLE_USER 를 가지고 있다.
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


    //유저 권한 정보를 가져오는 메소드 2개

    // 1. username을 기준으로 정보를 가져온다.
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    // 2. SecurityContext에 저장된 username의 정보만 가져 온다.
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}

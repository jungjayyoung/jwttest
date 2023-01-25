package com.jayjay.jwttest.repository;

import com.jayjay.jwttest.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    // @EntityGraph은 쿼리가 수행이 될때 Lazy 조회가 아니고 Eager
    // 조회로 authorities 정보를 같이 가져오게 된다.
    @EntityGraph(attributePaths = "authorities")
    // 이 메소드는 username을 기준으로 User 정보를 가져올때 권한 정보도 같이
    // 가져오게 된다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);

}

package com.example.jwt_security.repository;


import com.example.jwt_security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User,Integer> {

    User findByUsername(String username);

    @Modifying
    @Query(value = "update User u set u.password = :#{#user.password} where u.id = :#{#user.id}")
    void update(User user);
}

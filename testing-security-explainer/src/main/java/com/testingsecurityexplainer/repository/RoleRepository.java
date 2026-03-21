package com.testingsecurityexplainer.repository;

import com.testingsecurityexplainer.enums.RoleType;
import com.testingsecurityexplainer.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);
}

package com.security.sec.securitymodels.repositories;

import com.security.sec.securitymodels.ERole;
import com.security.sec.securitymodels.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface Rolerepo extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
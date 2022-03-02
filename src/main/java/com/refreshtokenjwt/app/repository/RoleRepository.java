package com.refreshtokenjwt.app.repository;

import com.refreshtokenjwt.app.modal.ERole;
import com.refreshtokenjwt.app.modal.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(ERole name);
}

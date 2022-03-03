package com.refreshtokenjwt.app.service;

import com.refreshtokenjwt.app.modal.ERole;
import com.refreshtokenjwt.app.modal.Role;

import java.util.Optional;

public interface IRoleService {
    Optional<Role> findByName(ERole name);
}

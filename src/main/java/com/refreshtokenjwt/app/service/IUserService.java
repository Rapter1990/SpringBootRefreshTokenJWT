package com.refreshtokenjwt.app.service;

import com.refreshtokenjwt.app.modal.RefreshToken;
import com.refreshtokenjwt.app.modal.User;

import java.util.Optional;

public interface IUserService {

    void saveUser(User user);
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    User findById(int userId);
}

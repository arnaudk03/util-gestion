package nyn.org.userservice.repository;

import nyn.org.userservice.model.ERole;
import nyn.org.userservice.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
package com.testingsecurityexplainer.config;

import com.testingsecurityexplainer.enums.RoleType;
import com.testingsecurityexplainer.model.Role;
import com.testingsecurityexplainer.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {
            Arrays.stream(RoleType.values()).forEach(roleType -> {
                if (roleRepository.findByName(roleType).isEmpty()) {
                    roleRepository.save(new Role(roleType));
                }
            });
        };
    }
}

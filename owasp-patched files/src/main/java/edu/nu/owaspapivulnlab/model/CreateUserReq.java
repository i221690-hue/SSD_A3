package edu.nu.owaspapivulnlab.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class CreateUserReq {
    @NotBlank
    private String username;

    @NotBlank
    @Size(min = 6, max = 100)
    private String password;

    @Email
    private String email;
}

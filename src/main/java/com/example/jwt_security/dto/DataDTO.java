package com.example.jwt_security.dto;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class DataDTO {

    private SessionDTO body;
    private ErrorDTO error;

    public DataDTO(SessionDTO body) {
        this.body = body;
    }

    public DataDTO(ErrorDTO error) {
        this.error = error;
    }
}

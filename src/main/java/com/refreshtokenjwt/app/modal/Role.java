package com.refreshtokenjwt.app.modal;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "Roles")
@Data
@NoArgsConstructor
public class Role extends IdBasedEntity implements Serializable {

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;

    public Role(ERole name){
        this.name = name;
    }

    public ERole getName() {
        return name;
    }
}

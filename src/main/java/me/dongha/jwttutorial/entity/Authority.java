package me.dongha.jwttutorial.entity;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "authority")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Authority {
    @Id
    @Column(name = "authority_name", length = 50)
    private String authorityName;// 권한명
}

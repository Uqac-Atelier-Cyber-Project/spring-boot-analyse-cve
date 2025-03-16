package com.uqac.analyse_cve.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * Représente une entrée de vulnérabilité
 */
@Getter
@Setter
@Builder
public class CveEntry {
    private String id;
    private String description;
}

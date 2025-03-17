package com.uqac.analyse_cve.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * Représente une entrée de vulnérabilité
 */
@Getter
@Setter
public class CveEntry {
    private String id;
    private String description;

    public CveEntry() {
        id="";
        description="";
    }

    public CveEntry(String id, String description) {
        this.id = id;
        this.description = description;
    }
    @Override
    public String toString() {
        return "CveEntry [id=" + id+"], " ;
    }
}

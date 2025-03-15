package com.uqac.analyse_cve.model;

/**
 * Représente une entrée de vulnérabilité
 */
public class CveEntry {
    private String id;
    private String description;

    public CveEntry(String id, String description) {
        this.id = id;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }
}

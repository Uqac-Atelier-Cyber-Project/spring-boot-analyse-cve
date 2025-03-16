package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import java.util.List;

/**
 * Représente un port scanné sur un hôte.
 */
public class NmapPort {

    @JacksonXmlProperty(isAttribute = true, localName = "portid")
    public int portid;
    private List<CveEntry> cves;
    @JacksonXmlProperty(localName = "state")
    public State state;

    @JacksonXmlProperty(localName = "service")
    public Service service;
    public void setCves(List<CveEntry> cves) {
        this.cves = cves;
    }

    @Override
    public String toString() {
        return (this.portid+" "+this.state.state+" "+this.service+" "+this.cves.toString());
    }
}

package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Représente le service détecté sur un port.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Service {

    @JacksonXmlProperty(isAttribute = true, localName = "name")
    public String name;

    @JacksonXmlProperty(isAttribute = true, localName = "version")
    public String version;

    public Service() {
        name=" ";
        version=" ";
    }
    @Override
    public String toString() {
        return "Service [name=" + name + ", version=" + version + "]";
    }

}

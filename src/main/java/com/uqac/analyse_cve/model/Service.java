package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Représente le service détecté sur un port.
 */
public class Service {

    @JacksonXmlProperty(isAttribute = true, localName = "name")
    public String name;

    @JacksonXmlProperty(isAttribute = true, localName = "version")
    public String version;
}

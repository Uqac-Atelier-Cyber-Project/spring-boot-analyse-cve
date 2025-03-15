package com.uqac.analyse_cve.model;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import java.util.List;

/**
 * Représente un hôte scanné dans le rapport Nmap.
 */
public class Host {

    @JacksonXmlProperty(localName = "address")
    public Address address;

    @JacksonXmlElementWrapper(localName = "ports")
    @JacksonXmlProperty(localName = "port")
    public List<NmapPort> ports;
}

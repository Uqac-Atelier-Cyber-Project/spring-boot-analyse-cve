package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Représente l'adresse IP d'un hôte.
 */
public class Address {
    @JacksonXmlProperty(localName = "addr", isAttribute = false) // Specify the element name
    public String ip;

    @JacksonXmlProperty(localName = "addrtype", isAttribute = false) // Map addrtype if necessary
    public String addrtype;
}


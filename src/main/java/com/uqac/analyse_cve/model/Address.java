package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Représente l'adresse IP d'un hôte.
 */
public class Address {
    @JacksonXmlProperty(isAttribute = true, localName = "addr")
    public String ip;
}


package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Représente l'état d'un port (open, closed, filtered...)
 */
public class State {

    @JacksonXmlProperty(isAttribute = true, localName = "state")
    public String state;
}

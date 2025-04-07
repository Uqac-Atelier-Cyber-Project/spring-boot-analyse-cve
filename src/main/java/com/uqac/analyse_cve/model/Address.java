package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/**
 * Représente l'adresse IP d'un hôte.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Address {
    @JacksonXmlProperty(localName = "addr", isAttribute = false) // Specify the element name
    public String ip;

    @JacksonXmlProperty(localName = "addrtype", isAttribute = false) // Map addrtype if necessary
    public String addrtype;

    public Address() {
        ip = "";
        addrtype = "";
    }


    @Override
    public String toString() {
        return "Address{" +
                "type='" + addrtype + '\'' +
                ", addr='" + ip + '\'' +
                '}';
    }
    public String toJson() {
        return "\"" + this.toString() + "\""; // Assuming Address has a proper toString method
    }
}


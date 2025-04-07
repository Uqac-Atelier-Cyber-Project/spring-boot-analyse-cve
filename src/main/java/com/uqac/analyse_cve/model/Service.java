package com.uqac.analyse_cve.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

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
        name = " ";
        version = " ";
    }



    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Service{name='").append(name).append('\'')
                .append(", version='").append(version).append('\'');

        sb.append("]}");
        return sb.toString();
    }
}
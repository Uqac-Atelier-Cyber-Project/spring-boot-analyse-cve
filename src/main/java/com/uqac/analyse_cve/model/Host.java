package com.uqac.analyse_cve.model;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * Représente un hôte scanné dans le rapport Nmap.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
public class Host {

    @JacksonXmlProperty(localName = "address")
    public Address address;

    @JacksonXmlElementWrapper(localName = "ports")
    @JacksonXmlProperty(localName = "port")
    public List<NmapPort> ports;


    /**
     * Builder
     * @param address
     */
    public Host(Address address) {
        this.address = address;
        this.ports = new ArrayList<NmapPort>();
    }
    public Host(){
        this.ports=new ArrayList<NmapPort>();
    }
    @Override
    public String toString() {
        return (this.address+": \n"+ this.ports.toString());
    }
}

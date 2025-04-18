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
import java.util.stream.Collectors;

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
    public Host() {
        this.ports = new ArrayList<NmapPort>();
    }

    /**
     * Builder
     * @param address
     */
    public Host(Address address) {
        this.address = address;
        this.ports = new ArrayList<NmapPort>();
    }
    @Override
    public String toString() {
        return "Host{" +
                "addresses=" + address +
                ", ports=" + ports +
                '}';
    }
    public String toJson() {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"address\":").append(address.toJson()).append(",");
        json.append("\"ports\":[").append(ports.stream()
                .map(NmapPort::toJson)
                .collect(Collectors.joining(","))).append("]");
        json.append("}");
        return json.toString();
    }
}

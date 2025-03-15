package com.uqac.analyse_cve.model;


import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

import java.util.List;

/**
 * Représente l'élément racine <nmaprun> du fichier XML généré par Nmap.
 */
@JacksonXmlRootElement(localName = "nmaprun")
public class NmapRun {

    @JacksonXmlElementWrapper(useWrapping = false)
    @JacksonXmlProperty(localName = "host")
    public List<Host> hosts;
}

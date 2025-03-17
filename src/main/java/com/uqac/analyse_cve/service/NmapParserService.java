package com.uqac.analyse_cve.service;


import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.uqac.analyse_cve.model.Host;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Service pour parser un fichier XML généré par Nmap et extraire les hôtes scannés.
 */
@Service
public class NmapParserService {
    private final XmlMapper xmlMapper;

    public NmapParserService() {
        this.xmlMapper = new XmlMapper();
    }

    /**
     * @param xmlPath : destination du xml généré par le nmap
     * @return
     */
    public List<Host> parseNmapXml(String xmlPath) {
        try {
            // Lire le fichier XML et le mapper en liste d'objets Host
            File xmlFile = new File(xmlPath);
            // Mapper l'XML en objets Host
            return xmlMapper.readValue(xmlFile, xmlMapper.getTypeFactory().constructCollectionType(List.class, Host.class));
        } catch (IOException e) {
            throw new RuntimeException("Erreur lors du parsing XML Nmap", e);
        }
    }
}

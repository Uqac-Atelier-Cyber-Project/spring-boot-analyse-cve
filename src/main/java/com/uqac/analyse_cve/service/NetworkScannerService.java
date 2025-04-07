package com.uqac.analyse_cve.service;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;

/**
 * Service pour scanner le réseau sur lequel est présent l'appareil
 */
@Service
public class NetworkScannerService {
    /**
     *
     * @param target : cible du nmap (domaine ou adresse réseau)
     * @return un XML qui résume les ports trouvés avec les noms des services et leur versions
     */

    public String runNmapScan(String target) {
        try {
            ProcessBuilder pb = new ProcessBuilder("Nmap", "-sV", "-oX", "nmap_result.xml", target);
            Process process = pb.start();
            process.waitFor();

            // Load and modify the XML
            File xmlFile = new File("nmap_result.xml");
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(xmlFile);
            doc.getDocumentElement().normalize();

            // Remove the problematic attributes
            NodeList timesNodes = doc.getElementsByTagName("times");
            for (int i = 0; i < timesNodes.getLength(); i++) {
                Element timesElement = (Element) timesNodes.item(i);
                timesElement.removeAttribute("srtt");
                timesElement.removeAttribute("rttvar");
                timesElement.removeAttribute("to");
            }

            // Save the modified XML back to the file
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(xmlFile);
            transformer.transform(source, result);

            return "nmap_result.xml";
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors du scan Nmap", e);
        }
    }
}

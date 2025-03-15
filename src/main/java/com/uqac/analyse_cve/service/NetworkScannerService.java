package com.uqac.analyse_cve.service;

import org.springframework.stereotype.Service;

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
            ProcessBuilder pb = new ProcessBuilder("nmap", "-sV", "-oX", "nmap_result.xml", target);
            Process process = pb.start();
            process.waitFor();
            return "nmap_result.xml";
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors du scan Nmap", e);
        }
    }
}

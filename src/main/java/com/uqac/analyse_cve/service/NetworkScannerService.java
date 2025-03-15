package com.uqac.analyse_cve.service;

import org.springframework.stereotype.Service;

@Service
public class NetworkScannerService {

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

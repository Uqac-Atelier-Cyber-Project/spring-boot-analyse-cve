package com.uqac.analyse_cve.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.uqac.analyse_cve.model.CveEntry;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Service qui trouve des CVE à partir des données collectées sur le réseau
 */
@Service
public class CveLookupService {

    private static final String CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz";
    private static final String OUTPUT_FILE = "nvdcve-1.1-recent.json.gz";
    /**
     * Télécharge automatiquement la base CVE chaque jour à 2h00 du matin.
     */
    @Scheduled(cron = "0 0 2 * * *") // tous les jours à 2h du matin
    public void updateCveDatabase() {
        try (BufferedInputStream in = new BufferedInputStream(new URL(CVE_URL).openStream());
             FileOutputStream fileOutputStream = new FileOutputStream(OUTPUT_FILE)) {
            byte dataBuffer[] = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                fileOutputStream.write(dataBuffer, 0, bytesRead);
            }
            System.out.println("[CVE Scheduler] Mise à jour de la base CVE téléchargée.");
        } catch (IOException e) {
            System.err.println("[CVE Scheduler] Erreur lors du téléchargement de la base CVE : " + e.getMessage());
        }
    }

    /**
     *
     * @param product : nom du service
     * @param version : version
     * @return cves : liste des cve concernées par le service et la version
     */
    public List<CveEntry> findCvesForService(String product, String version) {
        List<CveEntry> cves = new ArrayList<>();
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(new File("nvdcve-1.1-recent.json"));
            for (JsonNode item : root.get("CVE_Items")) {
                String description = item.get("cve").get("description").get("description_data").get(0).get("value").asText();
                if (description.toLowerCase().contains(product.toLowerCase()) &&
                    description.toLowerCase().contains(version.toLowerCase())) {
                    String id = item.get("cve").get("CVE_data_meta").get("ID").asText();
                    cves.add(new CveEntry(id, description));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors de la lecture des CVE", e);
        }
        return cves;
    }
}

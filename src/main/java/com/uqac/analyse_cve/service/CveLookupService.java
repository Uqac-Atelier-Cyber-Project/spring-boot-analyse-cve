package com.uqac.analyse_cve.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.uqac.analyse_cve.model.CveEntry;
import org.springframework.scheduling.annotation.Async;
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
     *
     * @param product : nom du service
     * @param version : version
     * @return cves : liste des cve concernées par le service et la version
     */
    @Async
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
                    cves.add(CveEntry.builder().id(id).description(description).build());
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors de la lecture des CVE", e);
        }
        return cves;
    }
}

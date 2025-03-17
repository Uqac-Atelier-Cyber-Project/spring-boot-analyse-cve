package com.uqac.analyse_cve.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uqac.analyse_cve.model.CveEntry;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Service qui trouve des CVE à partir des données collectées sur le réseau
 */
@Service
public class CveLookupService {

    private static final String CVE_FILE_PATH = "src/main/resources/nvdcve-1.1-recent.json"; // ou le bon chemin pour le fichier

    /**
     * Recherche des CVE pour un produit et une version donnés
     * @param product : nom du service
     * @param version : version
     * @return Liste des CVE concernées par le service et la version
     */
    public List<CveEntry> findCvesForService(String product, String version) {
        List<CveEntry> cves = new ArrayList<>();
        try {
            ObjectMapper mapper = new ObjectMapper();
            File cveFile = new File(CVE_FILE_PATH);

            // Vérifier si le fichier existe
            if (!cveFile.exists()) {
                throw new IOException("Le fichier des CVE n'a pas été trouvé : " + CVE_FILE_PATH);
            }

            JsonNode root = mapper.readTree(cveFile);
            if (root.has("CVE_Items")) {
                for (JsonNode item : root.get("CVE_Items")) {
                    JsonNode cveNode = item.get("cve");
                    if (cveNode != null) {
                        JsonNode descriptionNode = cveNode.get("description");
                        if (descriptionNode != null && descriptionNode.has("description_data")) {
                            String description = descriptionNode.get("description_data").get(0).get("value").asText();
                            if (description.toLowerCase().contains(product.toLowerCase()) &&
                                    description.toLowerCase().contains(version.toLowerCase())) {
                                String id = cveNode.get("CVE_data_meta").get("ID").asText();
                                cves.add(new CveEntry(id, description));
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Erreur lors de la lecture des CVE : " + e.getMessage(), e);
        }
        return cves;
    }
}

package com.uqac.analyse_cve.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uqac.analyse_cve.model.CveEntry;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Service qui trouve des CVE à partir des données collectées sur le réseau
 */
@Service
public class CveLookupService {

    private static final String CVE_RESOURCE_PATH = "/nvdcve-1.1-recent.json";

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
            // Extraire la ressource vers un fichier temporaire
            File tempFile = extractResourceToTempFile(CVE_RESOURCE_PATH);

            JsonNode root = mapper.readTree(tempFile);
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

    /**
     * Extrait une ressource du JAR vers un fichier temporaire
     * @param resourcePath Chemin de la ressource dans le JAR
     * @return Fichier temporaire contenant les données de la ressource
     * @throws IOException Si la ressource ne peut pas être extraite
     */
    private File extractResourceToTempFile(String resourcePath) throws IOException {
        // Obtenir le flux d'entrée pour la ressource
        InputStream inputStream = getClass().getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new IOException("Ressource non trouvée : " + resourcePath);
        }

        // Créer un fichier temporaire
        String tempFileName = "nvdcve-1.1-recent.json";
        File tempFile = new File(System.getProperty("java.io.tmpdir"), tempFileName);

        // Copier le contenu de la ressource dans le fichier temporaire
        try (FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        } finally {
            inputStream.close();
        }

        return tempFile;
    }
}
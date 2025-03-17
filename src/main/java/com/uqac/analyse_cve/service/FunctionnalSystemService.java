package com.uqac.analyse_cve.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.uqac.analyse_cve.DTO.ResponseRequest;
import com.uqac.analyse_cve.DTO.ServiceRequest;
import com.uqac.analyse_cve.model.Host;
import com.uqac.analyse_cve.model.NmapPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class FunctionnalSystemService {

    private final static Logger logger = LoggerFactory.getLogger(FunctionnalSystemService.class);
    @Autowired
    private NetworkScannerService scanner;

    @Autowired
    private NmapParserService parser;

    @Autowired
    private CveLookupService cveService;
    /**
     * Init Service Scan
     *
     * @param request Request
     */
    @Async
    public void scanInitService(ServiceRequest request) throws JsonProcessingException {
        logger.info("Start scan service");

        List<Host> cveHosts = new ArrayList<>();
        try {
            String xmlPath = scanner.runNmapScan(request.getOption());
            List<Host> hosts = parser.parseNmapXml(xmlPath);
            for (Host host : hosts) {
                for (NmapPort port : host.ports) {
                    // Vérification que port.service n'est pas null avant de l'utiliser
                    if (port.service != null && port.service.name != null && port.service.version != null) {
                        // Recherche des CVEs pour le service du port
                        port.setCves(cveService.findCvesForService(port.service.name, port.service.version));

                        // Création d'un nouvel objet Host pour ce port avec les CVEs
                        Host cveHost = new Host(host.address);
                        cveHost.ports.add(port);
                        cveHosts.add(cveHost);
                    } else {
                        // Log d'avertissement si port.service est null
                        logger.warn("Port service est null pour l'hôte " + host.address);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error during scan service: {}", e.getMessage());
        }

        callExternalService(request.getReportId(), cveHosts);
    }

    /**
     * Appelle un service externe pour envoyer le résultat du scan
     *
     * @param scanId   Identifiant du scan
     * @param cveHosts Résultat du scan
     * @throws JsonProcessingException Exception lors de la conversion en JSON
     */
    private void callExternalService(String scanId, List<Host> cveHosts) throws JsonProcessingException {

        logger.info(cveHosts.toString());

        RestTemplate restTemplate = new RestTemplate();
        String externalServiceUrl = "http://localhost:8090/report/analysisCVE";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        ResponseRequest scanResult = ResponseRequest.builder().reportId(scanId).cvehosts(cveHosts).build();

        HttpEntity<ResponseRequest> entity = new HttpEntity<>(scanResult, headers);
        try {
            restTemplate.postForObject(externalServiceUrl, entity, Void.class);
        } catch (ResourceAccessException e) {
            logger.error("Resource access error while posting scan result: {}", e.getMessage());
        } catch (HttpServerErrorException e) {
            logger.error("Server error while posting scan result: {}", e.getMessage());
        }
    }


}

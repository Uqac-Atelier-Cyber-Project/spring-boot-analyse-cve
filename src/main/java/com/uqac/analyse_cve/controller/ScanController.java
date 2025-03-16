package com.uqac.analyse_cve.controller;


import com.uqac.analyse_cve.DTO.ServiceRequest;
import com.uqac.analyse_cve.model.Host;
import com.uqac.analyse_cve.model.NmapPort;
import com.uqac.analyse_cve.service.CveLookupService;
import com.uqac.analyse_cve.service.FunctionnalSystemService;
import com.uqac.analyse_cve.service.NetworkScannerService;
import com.uqac.analyse_cve.service.NmapParserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.uqac.analyse_cve.DTO.*;


import java.util.Collections;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/scan")
public class ScanController {

    private static final Logger logger = LoggerFactory.getLogger(ScanController.class);



    @Autowired
    private FunctionnalSystemService functionnalSystemService;

    @PostMapping("/target")
    public String scan(@RequestBody ServiceRequest request) throws JsonProcessingException {
        logger.info("Start scan service");
        functionnalSystemService.scanInitService(request);
        return "CVE Scan launched";
    }



}

package com.uqac.analyse_cve.controller;


import com.uqac.analyse_cve.model.HostScanResult;
import com.uqac.analyse_cve.model.PortInfo;
import com.uqac.analyse_cve.service.CveLookupService;
import com.uqac.analyse_cve.service.NetworkScannerService;
import com.uqac.analyse_cve.service.NmapParserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/scan")
public class ScanController {

    @Autowired
    private NetworkScannerService scanner;

    @Autowired
    private NmapParserService parser;

    @Autowired
    private CveLookupService cveService;

    @GetMapping("/{target}")
    public List<HostScanResult> scan(@PathVariable String target) {
        String xmlPath = scanner.runNmapScan(target);
        List<HostScanResult> hosts = parser.parseNmapXml(xmlPath);
        for (HostScanResult host : hosts) {
            for (PortInfo port : host.getPorts()) {
                port.setCves(cveService.findCvesForService(port.getService(), port.getVersion()));
            }
        }
        return hosts;
    }
}

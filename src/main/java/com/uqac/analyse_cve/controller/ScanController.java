package com.uqac.analyse_cve.controller;


import com.uqac.analyse_cve.model.Host;
import com.uqac.analyse_cve.model.NmapPort;
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
    public List<Host> scan(@PathVariable String target) {
        String xmlPath = scanner.runNmapScan(target);
        List<Host> hosts = parser.parseNmapXml(xmlPath);
        for (Host host : hosts) {
            for (NmapPort port : host.ports) {
                port.setCves(cveService.findCvesForService(port.service.toString(), port.service.version));
            }
        }
        return hosts;
    }
}

package com.uqac.analyse_cve.service;


import com.uqac.analyse_cve.model.HostScanResult;
import com.uqac.analyse_cve.model.PortInfo;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class NmapParserService {

    public List<HostScanResult> parseNmapXml(String xmlPath) {
        List<HostScanResult> results = new ArrayList<>();
        /*
        try {

            SAXReader reader = new SAXReader();
            Document document = reader.read(new File(xmlPath));
            List<Element> hosts = document.getRootElement().elements("host");

            for (Element host : hosts) {
                String ip = host.element("address").attributeValue("addr");
                List<PortInfo> ports = new ArrayList<>();

                Element portsElement = host.element("ports");
                if (portsElement != null) {
                    for (Element portElement : portsElement.elements("port")) {
                        String port = portElement.attributeValue("portid");
                        String protocol = portElement.attributeValue("protocol");
                        Element serviceElement = portElement.element("service");
                        String name = serviceElement.attributeValue("name");
                        String version = serviceElement.attributeValue("version");

                        ports.add(new PortInfo(Integer.parseInt(port), protocol, name, version));
                    }
                }

                results.add(new HostScanResult(ip, ports));
            }

        } catch (Exception e) {
            throw new RuntimeException("Erreur lors du parsing XML Nmap", e);
        }*/
        return results;
    }
}

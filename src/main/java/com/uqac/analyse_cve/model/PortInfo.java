package com.uqac.analyse_cve.model;

import java.util.List;

public class PortInfo {
    private int port;
    private String protocol;
    private String service;
    private String version;
    private List<CveEntry> cves;

    public PortInfo(int port, String protocol, String service, String version) {
        this.port = port;
        this.protocol = protocol;
        this.service = service;
        this.version = version;
    }

    public void setCves(List<CveEntry> cves) {
        this.cves = cves;
    }

    public String getService() {
        return service;
    }

    public String getVersion() {
        return version;
    }
}

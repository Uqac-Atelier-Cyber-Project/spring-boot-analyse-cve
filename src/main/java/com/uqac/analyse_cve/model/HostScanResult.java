package com.uqac.analyse_cve.model;

import java.util.List;

public class HostScanResult {
    private String ip;
    private List<PortInfo> ports;

    public HostScanResult(String ip, List<PortInfo> ports) {
        this.ip = ip;
        this.ports = ports;
    }

    public String getIp() {
        return ip;
    }

    public List<PortInfo> getPorts() {
        return ports;
    }
}

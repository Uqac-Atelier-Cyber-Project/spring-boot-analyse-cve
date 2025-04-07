package com.uqac.analyse_cve.DTO;

import com.uqac.analyse_cve.model.Host;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@Builder
public class ResponseRequest {
    private String reportId;
    private List<Host> cvehosts;

    @Override
    public String toString() {
        return "ResponseRequest{" +
                "reportId='" + reportId + '\'' +
                ", cvehosts=" + cvehosts.stream()
                .map(Host::toJson)
                .collect(Collectors.joining(", ")) +
                '}';
    }
}
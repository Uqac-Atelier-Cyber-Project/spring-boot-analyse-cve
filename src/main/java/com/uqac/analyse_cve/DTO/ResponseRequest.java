package com.uqac.analyse_cve.DTO;

import com.uqac.analyse_cve.model.Host;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class ResponseRequest {
    private String reportId;
    private List<Host> cvehosts;
}

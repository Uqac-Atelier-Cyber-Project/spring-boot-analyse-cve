package com.uqac.analyse_cve;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;


@EnableAsync
@SpringBootApplication
public class AnalyseCveApplication {

	public static void main(String[] args) {
		SpringApplication.run(AnalyseCveApplication.class, args);
	}

}

package com.fakesnort.packetsniffer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * This class is used to Run the program.
 * @author Matej Lietava
 * @version 2020-08-01
 */
@Configuration
@EnableScheduling
@SpringBootApplication
public class Run {
    public static void main(String[] args) {
    	SpringApplication.run(Run.class, args);
    }
}
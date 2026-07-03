package com.noel.springsecurity.controllers;

import com.noel.springsecurity.dto.response.ApiMessageResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/health")
public class HealthController {

    @GetMapping
    public ResponseEntity<ApiMessageResponse> health() {
        return ResponseEntity.ok(new ApiMessageResponse(
                "Service is up and running...."
        ));
    }
}

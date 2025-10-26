package edu.nu.owaspapivulnlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// Safer error handling: do not leak exception types/messages to clients; log details server-side
@ControllerAdvice
public class GlobalErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handle(Exception e) {
        log.error("Unhandled exception", e);
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "internal_server_error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorMap);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        log.error("Database error", e);
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "database_error");
        return ResponseEntity.status(500).body(errorMap);
    }
}

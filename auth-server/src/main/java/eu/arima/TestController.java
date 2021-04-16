package eu.arima;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/")
    public String init() {
        return "Home page";
    }

    @GetMapping("/secure")
    public String secure() {
        return "Only authorized users can see this page";
    }
}

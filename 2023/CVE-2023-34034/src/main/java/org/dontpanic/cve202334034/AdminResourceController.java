package org.dontpanic.cve202334034;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/admin")
public class AdminResourceController {

    @GetMapping("/")
    public Mono<String> getPublicResource() {
        return Mono.just("hello admin!");
    }
}

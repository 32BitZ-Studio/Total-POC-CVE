package no.martinvks.catblog;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class AssetsController {
    @RequestMapping("/*/{path:[^\\.]+}")
    public String index() {
        return "forward:/";
    }
}

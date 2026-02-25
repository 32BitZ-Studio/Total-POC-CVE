package no.martinvks.catblog;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api")
public class CommentsController {
    private final List<Comment> comments = new ArrayList<>(Arrays.asList(
            new Comment(1, "Martin", "I can relate!"),
            new Comment(1, "Kasper", "Me too!")
    ));

    @GetMapping("/posts/{id}/comments")
    public List<Comment> getComments(@PathVariable int id) {
        return comments.stream()
                .filter(comment -> comment.getPostId() == id)
                .toList();
    }

    @PostMapping(path = "/posts/comments", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public void postComment(Comment comment, HttpServletResponse response) throws IOException {
        comments.add(comment);
        response.sendRedirect("/posts/" + comment.getPostId());
    }
}
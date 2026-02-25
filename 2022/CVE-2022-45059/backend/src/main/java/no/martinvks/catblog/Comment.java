package no.martinvks.catblog;

public class Comment {
    private final int postId;
    private final String name;
    private final String comment;

    public Comment(int postId, String name, String comment) {
        this.postId = postId;
        this.name = name;
        this.comment = comment;
    }

    public int getPostId() {
        return postId;
    }

    public String getName() {
        return name;
    }

    public String getComment() {
        return comment;
    }
}

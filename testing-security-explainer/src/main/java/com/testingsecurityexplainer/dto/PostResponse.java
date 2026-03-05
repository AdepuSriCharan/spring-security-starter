package com.testingsecurityexplainer.dto;

import com.testingsecurityexplainer.model.Post;

import java.time.Instant;

/**
 * Response payload for a single post.
 * Never exposes the raw entity directly.
 */
public class PostResponse {

    private Long id;
    private String title;
    private String content;
    private String authorId;
    private String authorUsername;
    private Instant createdAt;
    private Instant updatedAt;

    private PostResponse() {}

    /** Factory — builds a response from a JPA entity. */
    public static PostResponse from(Post post) {
        PostResponse r = new PostResponse();
        r.id = post.getId();
        r.title = post.getTitle();
        r.content = post.getContent();
        r.authorId = post.getAuthorId();
        r.authorUsername = post.getAuthorUsername();
        r.createdAt = post.getCreatedAt();
        r.updatedAt = post.getUpdatedAt();
        return r;
    }

    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getContent() { return content; }
    public String getAuthorId() { return authorId; }
    public String getAuthorUsername() { return authorUsername; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}

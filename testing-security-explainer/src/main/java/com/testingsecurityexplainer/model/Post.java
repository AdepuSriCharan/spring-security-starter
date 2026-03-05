package com.testingsecurityexplainer.model;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * JPA entity representing a blog post written by a user.
 *
 * <p>Used to demonstrate @RequireOwner — only the author can edit their post.
 * ADMIN users (with the "post:delete" permission) can delete any post.
 */
@Entity
@Table(name = "posts")
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    /** The ID of the user who created this post — used by @RequireOwner. */
    @Column(nullable = false)
    private String authorId;

    /** Denormalised username for display — avoids a join when listing posts. */
    @Column(nullable = false)
    private String authorUsername;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    protected Post() {}

    public Post(String title, String content, String authorId, String authorUsername) {
        this.title = title;
        this.content = content;
        this.authorId = authorId;
        this.authorUsername = authorUsername;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getContent() { return content; }
    public String getAuthorId() { return authorId; }
    public String getAuthorUsername() { return authorUsername; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    // ── Setters (only mutable fields) ────────────────────────────────────────

    public void setTitle(String title) { this.title = title; }
    public void setContent(String content) { this.content = content; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}

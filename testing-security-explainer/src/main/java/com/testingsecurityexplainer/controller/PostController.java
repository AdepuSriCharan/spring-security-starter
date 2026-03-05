package com.testingsecurityexplainer.controller;

import com.sricharan.security.core.annotation.RequirePermission;
import com.sricharan.security.core.annotation.RequireRole;
import com.testingsecurityexplainer.dto.CreatePostRequest;
import com.testingsecurityexplainer.dto.PostResponse;
import com.testingsecurityexplainer.dto.UpdatePostRequest;
import com.testingsecurityexplainer.service.PostService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * CRUD endpoints for blog posts.
 *
 * <p>Demonstrates two of the three authorization annotations:
 * <ul>
 *   <li>{@code @RequireRole("USER")}              — authenticated users can read / create / edit</li>
 *   <li>{@code @RequirePermission("post:delete")} — only ADMIN accounts carry this permission</li>
 * </ul>
 *
 * <p>Ownership enforcement for PUT /posts/{id} is handled inside
 * {@link PostService#updatePost} using {@code SecurityUserContext} —
 * because the owner ID has to be fetched from the DB and is not available
 * as a plain method parameter for the SpEL evaluator.
 *
 * <p>For a clean {@code @RequireOwner} demo with a URL-bound user ID, see
 * {@link MeController#getUserById}.
 *
 * <p>This controller is intentionally thin — all business logic lives in {@link PostService}.
 */
@RestController
@RequestMapping("/posts")
public class PostController {

    private final PostService postService;

    public PostController(PostService postService) {
        this.postService = postService;
    }

    /** Lists all posts. Any authenticated user with the USER role may read. */
    @GetMapping
    @RequireRole("USER")
    public List<PostResponse> getAllPosts() {
        return postService.getAllPosts();
    }

    /** Returns a single post by ID. */
    @GetMapping("/{id}")
    @RequireRole("USER")
    public PostResponse getPost(@PathVariable Long id) {
        return postService.getPostById(id);
    }

    /**
     * Creates a new post attributed to the currently authenticated user.
     * The author is resolved inside {@link PostService} from the security context —
     * never trusted from the request body.
     */
    @PostMapping
    @RequireRole("USER")
    public ResponseEntity<PostResponse> createPost(@Valid @RequestBody CreatePostRequest request) {
        PostResponse created = postService.createPost(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * Updates a post — any USER may attempt this, but {@link PostService#updatePost}
     * checks that the caller is the author and throws a 403 if not.
     * Ownership is enforced in the service layer using {@code SecurityUserContext}.
     */
    @PutMapping("/{id}")
    @RequireRole("USER")
    public PostResponse updatePost(
            @PathVariable Long id,
            @Valid @RequestBody UpdatePostRequest request) {
        return postService.updatePost(id, request);
    }

    /**
     * Deletes a post.
     * Requires the {@code post:delete} permission — only ADMIN accounts carry this.
     */
    @DeleteMapping("/{id}")
    @RequirePermission("post:delete")
    public ResponseEntity<Void> deletePost(@PathVariable Long id) {
        postService.deletePost(id);
        return ResponseEntity.noContent().build();
    }
}


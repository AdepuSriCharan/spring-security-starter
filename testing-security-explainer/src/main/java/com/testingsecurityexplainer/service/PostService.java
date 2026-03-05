package com.testingsecurityexplainer.service;

import com.sricharan.security.core.context.SecurityUserContext;
import com.sricharan.security.core.user.AuthenticatedUser;
import com.testingsecurityexplainer.dto.CreatePostRequest;
import com.testingsecurityexplainer.dto.PostResponse;
import com.testingsecurityexplainer.dto.UpdatePostRequest;
import com.testingsecurityexplainer.model.Post;
import com.testingsecurityexplainer.repository.PostRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Manages blog posts.
 *
 * <p>All methods that need the current caller resolve the user from
 * {@link SecurityUserContext} — keeping controllers thin and the identity
 * resolution in the service layer where it belongs.
 */
@Service
public class PostService {

    private final PostRepository postRepository;

    public PostService(PostRepository postRepository) {
        this.postRepository = postRepository;
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /** Returns all posts, newest first. */
    @Transactional(readOnly = true)
    public List<PostResponse> getAllPosts() {
        return postRepository.findAll().stream()
                .map(PostResponse::from)
                .toList();
    }

    /** Returns the post with the given ID or throws if not found. */
    @Transactional(readOnly = true)
    public PostResponse getPostById(Long id) {
        return PostResponse.from(requirePost(id));
    }

    // ── Mutations ─────────────────────────────────────────────────────────────

    /**
     * Creates a new post attributed to the currently authenticated user.
     * The caller's identity is pulled from {@link SecurityUserContext} —
     * never from client input.
     */
    @Transactional
    public PostResponse createPost(CreatePostRequest request) {
        AuthenticatedUser author = SecurityUserContext.requireCurrentUser();
        Post post = new Post(
                request.getTitle(),
                request.getContent(),
                author.getUserId(),
                author.getUsername()
        );
        return PostResponse.from(postRepository.save(post));
    }

    /**
     * Updates an existing post.
     *
     * <p>Ownership is enforced here in the service layer: the caller (from
     * {@link SecurityUserContext}) must be the original author. This is the
     * correct pattern when the owner ID is not available as a plain URL parameter
     * (and therefore cannot be used directly with {@code @RequireOwner} at the
     * controller level).
     *
     * @throws SecurityAuthorizationException if the caller is not the author
     */
    @Transactional
    public PostResponse updatePost(Long id, UpdatePostRequest request) {
        Post post = requirePost(id);
        AuthenticatedUser caller = SecurityUserContext.requireCurrentUser();

        if (!post.getAuthorId().equals(caller.getUserId())) {
            throw new com.sricharan.security.core.exception.SecurityAuthorizationException(
                    caller.getUsername(),
                    new String[]{},
                    java.util.Collections.emptySet(),
                    com.sricharan.security.core.exception.SecurityAuthorizationException.AuthorizationType.OWNERSHIP,
                    post.getAuthorId()
            );
        }

        post.setTitle(request.getTitle());
        post.setContent(request.getContent());
        post.setUpdatedAt(Instant.now());
        return PostResponse.from(postRepository.save(post));
    }

    /**
     * Deletes a post by ID.
     * Authorisation (@RequirePermission) is enforced at the controller level.
     */
    @Transactional
    public void deletePost(Long id) {
        Post post = requirePost(id);
        postRepository.delete(post);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Post requirePost(Long id) {
        return postRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Post not found: " + id));
    }
}

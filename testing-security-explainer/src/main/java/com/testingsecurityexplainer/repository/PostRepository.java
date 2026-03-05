package com.testingsecurityexplainer.repository;

import com.testingsecurityexplainer.model.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {

    /** All posts by a specific author — useful for "my posts" queries. */
    List<Post> findByAuthorIdOrderByCreatedAtDesc(String authorId);
}

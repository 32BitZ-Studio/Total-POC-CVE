<div class="w2dc-rating" <?php if ($meta_tags && $avg_rating->ratings_count): ?>itemprop="aggregateRating" itemscope itemtype="http://schema.org/AggregateRating"<?php endif; ?>>
	<?php if ($meta_tags && $avg_rating->ratings_count): ?>
	<?php if ($review_count = get_comments_number()): ?><meta itemprop="reviewCount" content="<?php echo $review_count; ?>" /><?php endif; ?>
	<meta itemprop="ratingValue" content="<?php echo $avg_rating->avg_value; ?>" />
	<meta itemprop="ratingCount" content="<?php echo $avg_rating->ratings_count; ?>" />
	<?php endif; ?>
	<?php if ($show_avg): ?>
	<span class="w2dc-rating-avgvalue">
		<span><?php echo $avg_rating->avg_value; ?></span>
	</span>
	<?php endif; ?>
	<div class="w2dc-rating-stars <?php if ($active): ?>w2dc-rating-active<?php endif; ?> <?php if (!empty($noajax)): ?>w2dc-rating-active-noajax<?php endif; ?>" <?php if (!empty($post_id)): ?>data-listing="<?php echo $post_id; ?>"<?php endif; ?> data-nonce="<?php echo wp_create_nonce('save_rating')?>">
		<label class="w2dc-rating-icon w2dc-fa <?php echo $avg_rating->render_star(5); ?>" <?php if (!empty($post_id)): ?>for="star-rating-5-<?php echo $post_id; ?>"<?php endif; ?> data-rating="5"></label>
		<label class="w2dc-rating-icon w2dc-fa <?php echo $avg_rating->render_star(4); ?>" <?php if (!empty($post_id)): ?>for="star-rating-4-<?php echo $post_id; ?>"<?php endif; ?> data-rating="4"></label>
		<label class="w2dc-rating-icon w2dc-fa <?php echo $avg_rating->render_star(3); ?>" <?php if (!empty($post_id)): ?>for="star-rating-3-<?php echo $post_id; ?>"<?php endif; ?> data-rating="3"></label>
		<label class="w2dc-rating-icon w2dc-fa <?php echo $avg_rating->render_star(2); ?>" <?php if (!empty($post_id)): ?>for="star-rating-2-<?php echo $post_id; ?>"<?php endif; ?> data-rating="2"></label>
		<label class="w2dc-rating-icon w2dc-fa <?php echo $avg_rating->render_star(1); ?>" <?php if (!empty($post_id)): ?>for="star-rating-1-<?php echo $post_id; ?>"<?php endif; ?> data-rating="1"></label>
		<?php if (!empty($noajax)): ?>
		<input type="hidden" name="w2dc-rating-noajax-<?php echo $post_id; ?>" class="w2dc-rating-noajax-value" value="<?php echo $avg_rating->avg_value; ?>">
		<?php endif; ?>
	</div>
</div>
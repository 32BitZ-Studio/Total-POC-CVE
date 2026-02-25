<!-- ratings_metabox.tpl.php -->
<div class="w2dc-ratings-overall-wrapper">
	<div class="w2dc-ratings-overall-avgvalue">
		<span class="w2dc-ratings-overall-stars">
				<?php echo _e('Average', 'W2DC'); ?>
		</span>
		<?php w2dc_renderTemplate(array(W2DC_RATINGS_TEMPLATES_PATH, 'avg_rating.tpl.php'), array('avg_rating' => $listing->avg_rating, 'post_id' => $listing->post->ID, 'meta_tags' => false, 'active' => false, 'show_avg' => true)); ?>
	</div>
	<?php foreach ($total_counts AS $rating=>$counts): ?>
	<div class="w2dc-ratings-overall">
		<span class="w2dc-ratings-overall-stars">
			<?php echo $rating; ?> <?php echo _n('Star ', 'Stars', $rating, 'W2DC'); ?>
		</span>
		<div class="w2dc-rating">
			<div class="w2dc-rating-stars">
				<label class="w2dc-rating-icon w2dc-fa <?php echo ($rating >= 5) ? 'w2dc-fa-star' : 'w2dc-fa-star-o' ?>"></label>
				<label class="w2dc-rating-icon w2dc-fa <?php echo ($rating >= 4) ? 'w2dc-fa-star' : 'w2dc-fa-star-o' ?>"></label>
				<label class="w2dc-rating-icon w2dc-fa <?php echo ($rating >= 3) ? 'w2dc-fa-star' : 'w2dc-fa-star-o' ?>"></label>
				<label class="w2dc-rating-icon w2dc-fa <?php echo ($rating >= 2) ? 'w2dc-fa-star' : 'w2dc-fa-star-o' ?>"></label>
				<label class="w2dc-rating-icon w2dc-fa <?php echo ($rating >= 1) ? 'w2dc-fa-star' : 'w2dc-fa-star-o' ?>"></label>
			</div>
		</div>
	 	&nbsp;&nbsp; - &nbsp;&nbsp;<span class="w2dc-ratings-counts"><?php echo $counts; ?> (<?php echo $listing->avg_rating->get_percents_counts($counts); ?>%)</span>
	 </div>
	<?php endforeach; ?>
</div>
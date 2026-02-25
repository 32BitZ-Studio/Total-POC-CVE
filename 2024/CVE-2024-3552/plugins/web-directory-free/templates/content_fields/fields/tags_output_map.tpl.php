<?php if (has_term('', W2DC_TAGS_TAX, $listing->post->ID)): ?>
	<?php echo get_the_term_list($listing->post->ID, W2DC_TAGS_TAX, '', ', ', ''); ?>
<?php endif; ?>
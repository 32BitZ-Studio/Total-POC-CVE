<?php if (has_term('', W2DC_CATEGORIES_TAX, $listing->post->ID)): ?>
	<?php echo get_the_term_list($listing->post->ID, W2DC_CATEGORIES_TAX, '', ', ', ''); ?>
<?php endif; ?>
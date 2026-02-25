<div class="wcsearch-search-input" <?php echo $search_model->getOptionsString(); ?>>
	<div class="wcsearch-search-input-more-filters" data-status="<?php echo ($opened) ? 'opened':  'closed'; ?>">
		<?php echo esc_html($text); ?> <span class="wcsearch-fa wcsearch-fa-chevron-<?php echo ($opened) ? 'up': 'down'; ?>"></span>
		<input type="hidden" name="more_filters" value="<?php echo (int)$opened; ?>">
	</div>
</div>
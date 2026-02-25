<div class="wcsearch-search-input <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<?php 
	$params = array(
			'functionality' => 'wcsearch-keywords-autocomplete',
			'placeholder' => $placeholder,
			'autocomplete_field' => 'keywords',
			'autocomplete_field_value' => $values,
			'autocomplete_ajax' => $autocomplete,
	);
	wcsearch_tax_dropdowns_menu_init($params);
	?>
	
	<?php wcsearch_print_suggestions_code($try_to_search_text, $keywords_suggestions); ?>
</div>
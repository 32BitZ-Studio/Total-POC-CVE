<div class="wcsearch-search-model-input wcsearch-search-model-input-field" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-has-feedback">
		<span class="wcsearch-form-control"><?php echo esc_html($placeholder); ?></span>
		<span class="wcsearch-dropdowns-menu-button wcsearch-form-control-feedback wcsearch-fa wcsearch-fa-map-marker"></span>
	</div>
	
	<?php wcsearch_print_suggestions_code($try_to_search_text, $address_suggestions); ?>
</div>
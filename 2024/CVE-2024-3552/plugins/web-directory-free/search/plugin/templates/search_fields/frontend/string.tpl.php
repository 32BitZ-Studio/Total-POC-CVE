<div class="wcsearch-search-input" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-has-feedback">
		<input type="text" class="wcsearch-form-control wcsearch-search-string-input" name="<?php echo esc_attr($slug); ?>" placeholder="<?php echo esc_html($placeholder); ?>" value="<?php echo esc_attr(stripslashes($values)); ?>" />
		<span class="wcsearch-dropdowns-menu-button wcsearch-form-control-feedback wcsearch-fa wcsearch-fa-search"></span>
	</div>
	
	<?php wcsearch_print_suggestions_code($try_to_search_text, $keywords_suggestions); ?>
</div>
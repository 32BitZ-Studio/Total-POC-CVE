<div class="wcsearch-search-input wcsearch-search-inputs <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<?php
	$min_value = '';
	$max_value = '';
	if ($values && ($_values = explode('-', $values))) {
		$min_value = $_values[0];
		$max_value = $_values[1];
	} 
	?>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-inputs-wrapper">
		<input type="hidden" name="<?php echo esc_attr($slug); ?>" value="<?php echo esc_attr($values); ?>">
		<input type="text" name="field_<?php echo esc_attr($slug); ?>_min" class="wcsearch-form-control wcsearch-search-input-1 wcsearch-search-exclude-this-input" value="<?php echo esc_attr($min_value); ?>" placeholder="<?php esc_attr_e('Min price', 'WCSEARCH'); ?>" />
		<input type="text" name="field_<?php echo esc_attr($slug); ?>_max" class="wcsearch-form-control wcsearch-search-input-2 wcsearch-search-exclude-this-input" value="<?php echo esc_attr($max_value); ?>" placeholder="<?php esc_attr_e('Max price', 'WCSEARCH'); ?>" />
	</div>
</div>
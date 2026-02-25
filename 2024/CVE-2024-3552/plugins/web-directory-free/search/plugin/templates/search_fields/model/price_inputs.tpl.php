<div class="wcsearch-search-model-input wcsearch-search-model-two-inputs" <?php echo $search_model->getOptionsString(); ?>>
	<?php
	$min_value = '';
	$max_value = '';
	if ($values && ($values = explode('-', $values))) {
		$min_value = $values[0];
		$max_value = $values[1];
	} 
	?>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-model-input-clear">
		<input type="text" name="field_<?php echo esc_attr($slug); ?>_min" class="wcsearch-form-control wcsearch-search-model-input-1" value="<?php echo esc_attr($min_value); ?>" placeholder="<?php esc_attr_e('Min price', 'WCSEARCH'); ?>" />
		<input type="text" name="field_<?php echo esc_attr($slug); ?>_max" class="wcsearch-form-control wcsearch-search-model-input-2" value="<?php echo esc_attr($max_value); ?>" placeholder="<?php esc_attr_e('Max price', 'WCSEARCH'); ?>" />
	</div>
</div>
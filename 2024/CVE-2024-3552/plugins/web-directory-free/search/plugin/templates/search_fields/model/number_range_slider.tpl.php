<div class="wcsearch-search-model-input wcsearch-search-model-input-range" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	
	<?php
	wcsearch_print_range_slider_code(
		array(
			'min_max_options' => $min_max_options,
			'values' => $values,
			'slug' => $slug,
			'field_name' => $slug,
			'show_scale' => $show_scale,
			'odd_even_labels' => $odd_even_labels,
			'string_label' => "",
			'used_by' => $used_by,
			'is_number' => $is_number,
		)
	); ?>
</div>
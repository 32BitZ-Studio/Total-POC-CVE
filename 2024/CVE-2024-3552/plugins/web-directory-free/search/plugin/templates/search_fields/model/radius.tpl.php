<div class="wcsearch-search-model-input wcsearch-search-model-input-single-slider" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-model-search-input-label"><?php echo esc_html($title); ?></label>
	<?php
	if ($mode == 'slider') {
		wcsearch_print_radius_slider_code(
			array(
				'min_max_options' => $min_max_options,
				'values' => $values,
				'slug' => 'radius',
				'show_scale' => $show_scale,
				'odd_even_labels' => $odd_even_labels,
				'string_label' => (esc_html__("Search in radius ", "WCSEARCH") != 'Search in radius ' ? esc_html__("Search in radius ", "WCSEARCH") : $string_label),
			)
		);
	} else {
		wcsearch_print_radius_selectbox_code(
			array(
					'min_max_options' => $min_max_options,
					'values' => $values,
					'slug' => 'radius',
			)
		);
	}
	?>
</div>
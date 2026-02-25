<div class="wcsearch-search-input wcsearch-search-input-tax-range <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	
	<?php
	
	$index = wcsearch_generateRandomVal();
	
	wcsearch_print_slider_code(
		array(
			'min_max_options' => $min_max_options,
			'values' => $values,
			'index' => $index,
			'slug' => 'tax_'.$tax_name,
			'tax' => $tax_name,
			'field_name' => 'tax_' . $slug,
			'show_scale' => true,
			'string_label' => "", //esc_html__("Price:", "WCSEARCH"),
		)
	);
	?>
</div>
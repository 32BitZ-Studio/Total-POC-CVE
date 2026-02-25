<div class="wcsearch-search-input wcsearch-search-input-tax-select <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	
	<?php
	if ($mode == 'hierarhical_dropdown') {
		
		if (!isset($placeholders) && isset($placeholder)) {
			$placeholders = $placeholder;
		} else if ($placeholders === false) {
			$taxonomy_obj = get_taxonomy($tax);
			$placeholder = $taxonomy_obj->labels->singular_name;
		} elseif (!is_array($placeholders) && json_decode($placeholders)) {
			$placeholders = json_decode($placeholders);
			$placeholder = $placeholder[0];
		} elseif (!empty($placeholders)) {
			$placeholder = $placeholders;
		} elseif (!empty($placeholder)) {
			$placeholders = $placeholder;
		}
		
		$params = array(
				'tax' => $tax_name,
				'field_name' => $slug,
				'depth' => $depth,
				'term_id' => $values,
				'count' => $counter,
				'hide_empty' => $hide_empty,
				'exact_terms' => $exact_terms,
				'orderby' => $orderby,
				'order' => $order,
				'placeholders' => $placeholders,
				'functionality' => 'wcsearch-heirarhical-dropdown',
		);
		wcsearch_heirarhical_dropdowns_menu_init($params);
		
	} else {
		$params = array(
				'tax' => $tax_name,
				'field_name' => $slug,
				'depth' => $depth,
				'term_id' => $values,
				'count' => $counter,
				'uID' => null,
				'open_on_click' => $open_on_click,
				'hide_empty' => $hide_empty,
				'exact_terms' => $exact_terms,
				'orderby' => $orderby,
				'order' => $order,
				'placeholder' => $placeholder,
				'place_id' => wcsearch_get_query_string('place_id'),
		);
		
		if ($mode == 'dropdown') {
			$functionality_class = 'wcsearch-tax-autocomplete';
		} elseif ($mode == 'multi_dropdown') {
			$functionality_class = 'wcsearch-multiselect-dropdown';
		} elseif ($mode == 'dropdown_keywords') {
			$functionality_class = 'wcsearch-tax-keywords';
		} elseif ($mode == 'dropdown_address') {
			$functionality_class = 'wcsearch-tax-address';
		}
		
		$params['functionality'] = $functionality_class;
		
		if ($mode == 'dropdown_keywords') {
			$params['autocomplete_field'] = 'keywords';
			$params['autocomplete_field_value'] = $keywords_value;
			$params['autocomplete_ajax'] = true;
		}
		if ($mode == 'dropdown_address') {
			$params['autocomplete_field'] = 'address';
			$params['autocomplete_field_value'] = $address_value;
		}
		wcsearch_tax_dropdowns_menu_init($params);
	}
	?>
	
	<?php if ($mode == "dropdown_address") wcsearch_print_suggestions_code($try_to_search_text, $address_suggestions); ?>
	<?php if ($mode == "dropdown_keywords") wcsearch_print_suggestions_code($try_to_search_text, $keywords_suggestions); ?>
</div>
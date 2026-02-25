<div class="wcsearch-search-model-input wcsearch-search-model-input-tax-select" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	
	<?php
	if ($mode == 'multi_dropdown') {
	
		$term_id = 0;
		
		if (is_numeric($values)) {
			$term_id = $values;
		} else {
			$term_id = explode(',', $values);
		}
		$functionality_class = 'wcsearch-multiselect-dropdown';
		
		$params = array(
				'tax' => $tax_name,
				'field_name' => $slug,
				'depth' => $depth,
				'term_id' => $term_id,
				'count' => $counter,
				'uID' => null,
				'hide_empty' => $hide_empty,
				'functionality' => $functionality_class,
				'orderby' => $orderby,
				'order' => $order,
				'placeholder' => $placeholder,
		);
		wcsearch_tax_dropdowns_menu_init($params);
	} else {
		
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
		}

		/* $params = array(
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
		wcsearch_heirarhical_dropdowns_menu_init($params); */
	
	
	?>
	<select name="field_<?php echo esc_attr($slug); ?>" name="field_<?php echo esc_attr($slug); ?>" class="wcsearch-form-control">
		<option value=""><?php echo esc_html($placeholder); ?></option>
		<?php foreach ($selection_items AS $key=>$item): ?>
		<option value="<?php echo esc_attr($item->term_id); ?>" <?php selected($values, $item->term_id); ?>><?php esc_html_e($item->name); ?> <?php if ($counter): echo ' ('.$item->count.')'; endif; ?></option>
		<?php endforeach; ?>
	</select>
	<?php
	}
	?>
	
	<?php if ($mode == "dropdown_address") wcsearch_print_suggestions_code($try_to_search_text, $address_suggestions); ?>
	<?php if ($mode == "dropdown_keywords") wcsearch_print_suggestions_code($try_to_search_text, $keywords_suggestions); ?>
</div>
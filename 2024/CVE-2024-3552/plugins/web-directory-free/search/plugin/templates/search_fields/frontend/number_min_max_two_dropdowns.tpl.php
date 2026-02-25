<div class="wcsearch-search-input wcsearch-search-input-two-selects <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-inputs-wrapper">
		<?php
		$min_value = '';
		$max_value = '';
		if ($values && ($_values = explode('-', $values)) && count($_values) == 2) {
			$min_value = $_values[0];
			$max_value = $_values[1];
		}
		$min_max_labels = wcsearch_format_number_labels($min_max_options, $used_by, $slug);
		
		if ($min_max_labels): ?>
		<input type="hidden" name="<?php echo esc_attr($slug); ?>" value="<?php echo esc_attr($values); ?>">
		<?php $i = 0; ?>
		<select name="field_<?php echo esc_attr($slug); ?>_min" class="wcsearch-form-control wcsearch-search-input-1 wcsearch-search-exclude-this-input">
			<option value=""><?php echo esc_html($placeholder_min); ?></option>
			<?php while ($i < count($min_max_labels)-1): ?>
			<option value="<?php echo esc_attr($min_max_options[$i]); ?>" <?php selected($min_value, $min_max_options[$i]); ?>><?php echo wcsearch_number_option_label($min_max_labels[$i]); ?></option>
			<?php $i++; ?>
			<?php endwhile; ?>
		</select>
		
		<?php $i = 1; ?>
		<select name="field_<?php echo esc_attr($slug); ?>_max" class="wcsearch-form-control wcsearch-search-input-2 wcsearch-search-exclude-this-input">
			<option value=""><?php echo esc_html($placeholder_max); ?></option>
			<?php while ($i < count($min_max_labels)): ?>
			<option value="<?php echo esc_attr($min_max_options[$i]); ?>" <?php selected($max_value, $min_max_options[$i]); ?>><?php echo wcsearch_number_option_label($min_max_labels[$i]); ?></option>
			<?php $i++; ?>
			<?php endwhile; ?>
		</select>
		<?php endif; ?>
	</div>
</div>
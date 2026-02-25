<div class="wcsearch-search-model-input wcsearch-search-model-input-two-selects" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-model-input-clear">
		<?php
		$min_value = '';
		$max_value = '';
		if ($values && ($values = explode('-', $values))) {
			$min_value = $values[0];
			$max_value = $values[1];
		}
		
		$min_max_options = array_filter(array_map('trim', explode(',', $min_max_options)));
		foreach ($min_max_options AS $key=>$value) {
			if (is_numeric($value)) {
				$min_max_options[$key] = wcsearch_price_format($value);
			}
		}
		if ($min_max_options): ?>
		<?php $i = 0; ?>
		<select name="field_<?php echo esc_attr($slug); ?>_min" class="wcsearch-form-control wcsearch-search-model-input-1">
			<option value=""><?php esc_html_e("Select min price", "WCSEARCH"); ?></option>
			<?php while ($i < count($min_max_options)-1): ?>
			<option value="<?php echo esc_attr($i); ?>" <?php selected($min_value, $i); ?>><?php echo wcsearch_price_option_label($min_max_options[$i]); ?></option>
			<?php $i++; ?>
			<?php endwhile; ?>
		</select>
		
		<?php $i = 1; ?>
		<select name="field_<?php echo esc_attr($slug); ?>_max" class="wcsearch-form-control wcsearch-search-model-input-2">
			<option value=""><?php esc_html_e("Select max price", "WCSEARCH"); ?></option>
			<?php while ($i < count($min_max_options)): ?>
			<option value="<?php echo esc_attr($i); ?>" <?php selected($max_value, $i); ?>><?php echo wcsearch_price_option_label($min_max_options[$i]); ?></option>
			<?php $i++; ?>
			<?php endwhile; ?>
		</select>
		<?php endif; ?>
	</div>
</div>
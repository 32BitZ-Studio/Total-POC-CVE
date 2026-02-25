<div class="wcsearch-search-model-input wcsearch-search-model-input-two-selects" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-model-input-clear">
		<?php
		$min_value = '';
		$max_value = '';
		if ($values && ($_values = explode('-', $values))) {
			$min_value = $_values[0];
			$max_value = $_values[1];
		}
		$min_max_labels = wcsearch_format_number_labels($min_max_options, $used_by, $slug);
		
		if ($min_max_options): ?>
		<?php $i = 0; ?>
		<select name="field_<?php echo esc_attr($slug); ?>_min" class="wcsearch-form-control wcsearch-search-model-input-1">
			<option value=""><?php echo esc_html($placeholder_min); ?></option>
			<?php while ($i < count($min_max_options)-1): ?>
			<option value="<?php echo esc_attr($i); ?>" <?php selected($min_value, $i); ?>><?php echo wcsearch_number_option_label($min_max_options[$i]); ?></option>
			<?php $i++; ?>
			<?php endwhile; ?>
		</select>
		
		<?php $i = 1; ?>
		<select name="field_<?php echo esc_attr($slug); ?>_max" class="wcsearch-form-control wcsearch-search-model-input-2">
			<option value=""><?php echo esc_html($placeholder_max); ?></option>
			<?php while ($i < count($min_max_options)): ?>
			<option value="<?php echo esc_attr($i); ?>" <?php selected($max_value, $i); ?>><?php echo wcsearch_number_option_label($min_max_options[$i]); ?></option>
			<?php $i++; ?>
			<?php endwhile; ?>
		</select>
		<?php endif; ?>
	</div>
</div>
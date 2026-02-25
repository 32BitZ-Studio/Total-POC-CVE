<div class="wcsearch-search-model-input wcsearch-search-model-input-one-select" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<?php
	if ($min_max_options): ?>
		<select name="<?php echo esc_attr($slug); ?>" class="wcsearch-form-control">
			<option value="0"><?php echo esc_html($placeholder_single_dropdown); ?></option>
			<?php foreach (wcsearch_get_number_labels($min_max_options, $used_by, $slug) AS $option_label=>$option_value): ?>
			<option value="<?php echo esc_attr($option_value); ?>" <?php if ($values == $option_value)  echo 'selected'; ?>><?php echo wcsearch_number_option_label($option_label); ?></option>
			<?php endforeach; ?>
		</select>
	<?php endif; ?>
</div>
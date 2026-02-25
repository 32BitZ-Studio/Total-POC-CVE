<div class="wcsearch-search-input wcsearch-search-input-one-select <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-inputs-wrapper">
	<?php
	if ($min_max_options): ?>
		<select name="<?php echo esc_attr($slug); ?>" class="wcsearch-form-control wcsearch-search-input-single-select">
			<option value="0"><?php esc_html_e("Select price range", "WCSEARCH"); ?></option>
			<?php foreach (wcsearch_get_price_labels($min_max_options) AS $option_label=>$option_value): ?>
			<option value="<?php echo esc_attr($option_value); ?>" <?php if ($values == $option_value)  echo 'selected'; ?>><?php echo wcsearch_price_option_label($option_label); ?></option>
			<?php endforeach; ?>
		</select>
	<?php endif; ?>
	</div>
</div>
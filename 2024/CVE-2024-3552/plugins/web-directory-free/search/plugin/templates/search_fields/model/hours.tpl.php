<div class="wcsearch-search-model-input wcsearch-search-model-hours" <?php echo $search_model->getOptionsString(); ?>>
	<?php if ($display == "checkbox"): ?>
	<div class="wcsearch-checkbox">
		<label class="wcsearch-search-model-input-label">
			<input type="checkbox" name="" value="1" <?php if ($values) echo 'checked'; ?> /> <?php echo esc_html($label); ?> <?php if ($counter): ?>(<?php echo esc_html($counter_value); ?>)<?php endif; ?>
		</label>
	</div>
	<?php elseif ($display == "button"): ?>
	<div class="wcsearch-search-term-button <?php if ($values): ?>wcsearch-search-term-button-active<?php endif; ?>" data-term-id="1">
		<div class="wcsearch-btn wcsearch-btn-default wcsearch-term-id-<?php echo esc_attr($slug); ?>"><?php echo esc_html($label); ?><?php if ($counter): ?> (<?php echo esc_html($counter_value); ?>)<?php endif; ?></div>
	</div>
	<input type="hidden" name="<?php echo esc_attr($slug); ?>" class="wcsearch-search-terms-buttons-input" value="<?php echo esc_attr($values); ?>">
	<?php endif; ?>
</div>
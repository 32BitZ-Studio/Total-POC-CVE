<div class="wcsearch-search-model-input wcsearch-search-model-featured" <?php echo $search_model->getOptionsString(); ?>>
	<div class="wcsearch-checkbox">
		<label class="wcsearch-search-model-input-label">
			<input type="checkbox" name="" value="1" <?php if ($values) echo 'checked'; ?> /> <?php echo esc_html($label); ?> <?php if ($counter): ?>(<?php echo esc_html($counter_value); ?>)<?php endif; ?>
		</label>
	</div>
</div>
<div class="wcsearch-search-input wcsearch-search-hours" <?php echo $search_model->getOptionsString(); ?>>
	<?php if ($display == "checkbox"): ?>
	<div class="wcsearch-checkbox">
		<label class="wcsearch-search-input-label">
			<input type="checkbox" name="<?php echo esc_attr($slug); ?>" value="1" <?php if ($values) echo 'checked'; ?> /> <?php echo esc_html($label); ?><?php if ($counter): ?> (<?php echo wcsearch_get_count(array('hours' => $slug, 'used_by' => $used_by)); ?>)<?php endif; ?>
		</label>
	</div>
	<?php elseif ($display == "button"): ?>
	<div class="wcsearch-search-term-button <?php if ($values): ?>wcsearch-search-term-button-active<?php endif; ?>" data-term-id="1">
		<div class="wcsearch-btn wcsearch-btn-default wcsearch-term-id-<?php echo esc_attr($slug); ?>"><?php echo esc_html($label); ?><?php if ($counter): ?> (<?php echo wcsearch_get_count(array('hours' => $slug, 'used_by' => $used_by)); ?>)<?php endif; ?></div>
	</div>
	<input type="hidden" name="<?php echo esc_attr($slug); ?>" class="wcsearch-search-terms-buttons-input" value="<?php echo esc_attr($values); ?>">
	<?php endif; ?>
</div>
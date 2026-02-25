<div class="wcsearch-search-input wcsearch-search-featured" <?php echo $search_model->getOptionsString(); ?>>
	<div class="wcsearch-checkbox">
		<label class="wcsearch-search-input-label">
			<input type="checkbox" name="featured" value="1" <?php if ($values) echo 'checked'; ?> /> <?php echo esc_html($label); ?> <?php if ($counter): ?>(<?php echo wcsearch_get_count(array('option' => 'featured', 'used_by' => $used_by)); ?>)<?php endif; ?>
		</label>
	</div>
</div>
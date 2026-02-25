<div class="wcsearch-search-input wcsearch-search-onsale" <?php echo $search_model->getOptionsString(); ?>>
	<div class="wcsearch-checkbox">
		<label class="wcsearch-search-input-label">
			<input type="checkbox" name="onsale" value="1" <?php if ($values) echo 'checked'; ?> /> <?php echo esc_html($label); ?> <?php if ($counter): ?>(<?php echo wcsearch_get_count(array('option' => 'onsale', 'used_by' => $used_by)); ?>)<?php endif; ?>
		</label>
	</div>
</div>
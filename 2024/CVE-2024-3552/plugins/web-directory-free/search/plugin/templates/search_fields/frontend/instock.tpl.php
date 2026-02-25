<div class="wcsearch-search-input wcsearch-search-instock" <?php echo $search_model->getOptionsString(); ?>>
	<div class="wcsearch-checkbox">
		<label class="wcsearch-search-input-label">
			<input type="checkbox" name="instock" value="1" <?php if ($values) echo 'checked'; ?> /> <?php echo esc_html($label); ?> <?php if ($counter): ?>(<?php echo wcsearch_get_count(array('option' => 'instock', 'used_by' => $used_by)); ?>)<?php endif; ?>
		</label>
	</div>
</div>
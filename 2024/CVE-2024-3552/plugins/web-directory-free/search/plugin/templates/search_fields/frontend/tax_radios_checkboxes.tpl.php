<?php
if (!empty($terms_options)) :
foreach ($selection_items AS $key=>$item):
	if ($color = wcsearch_get_term_option($terms_options, $item->term_id, 'color')): ?>
	<style data-term-id="<?php echo esc_attr($item->term_id); ?>">
	#<?php echo esc_attr($search_model->id); ?> .wcsearch-term-id-<?php echo esc_attr($item->term_id); ?> .wcsearch-control-indicator { background-color: <?php echo esc_attr($color); ?> !important; }
	<?php if (wcsearch_get_luma_color($color) > 205) { $tick_color = '#757575'; } else { $tick_color = '#FFFFFF'; }
	if (wcsearch_get_luma_color($color) > 205) { $tick_color = '#757575'; } ?>
	#<?php echo esc_attr($search_model->id); ?> .wcsearch-term-id-<?php echo esc_attr($item->term_id); ?> .wcsearch-control-indicator::after { color: <?php echo esc_attr($tick_color); ?> !important; }
	#<?php echo esc_attr($search_model->id); ?> .wcsearch-radio.wcsearch-term-id-<?php echo esc_attr($item->term_id); ?> .wcsearch-control-indicator::after { background-color: <?php echo esc_attr($tick_color); ?> !important; }
	<?php endif; ?>
	</style>
<?php
endforeach;
endif; ?>
<div class="wcsearch-search-input wcsearch-search-input-<?php echo esc_attr($mode); ?> <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-input-terms-columns" <?php if ($height_limit): ?>style="height: <?php echo $height_limit; ?>px;"<?php endif; ?>>
	<?php
	if ($selection_items):
		$i = 1;
		while ($i <= $columns): ?>
		<div class="wcsearch-search-input-terms-column wcsearch-search-input-<?php echo esc_attr($mode); ?>-column wcsearch-search-input-terms-column-<?php echo esc_attr($columns); ?> wcsearch-search-input-<?php echo esc_attr($mode); ?>-column-<?php echo esc_attr($columns); ?>">
			<?php $j = 1; ?>
			<?php foreach ($selection_items AS $key=>$item): ?>
				<?php if ($i == $j): ?>
				<div class="<?php if ($mode =='checkboxes'): ?>wcsearch-checkbox<?php elseif ($mode =='radios'): ?>wcsearch-radio<?php endif; ?> wcsearch-term-id-<?php echo esc_attr($item->term_id); ?>">
					<label>
					<?php if ($mode =='checkboxes'): ?>
						<input type="checkbox" name="<?php echo esc_attr($slug); ?>" value="<?php echo esc_attr($item->term_id); ?>" <?php if ($values && in_array($item->term_id, explode(',', $values)))  echo 'checked'; ?> />
					<?php elseif ($mode =='radios'): ?>
						<input type="radio" name="<?php echo esc_attr($slug); ?>" value="<?php echo esc_attr($item->term_id); ?>" <?php if ($values && in_array($item->term_id, explode(',', $values)))  echo 'checked'; ?> />
					<?php endif; ?>
					<?php echo esc_html($item->name); ?><?php if ($counter): echo ' ('.wcsearch_get_count(array('mode' => $mode, 'term' => $item, 'used_by' => $used_by)).')'; endif; ?>
					</label>
				</div>
				<?php endif; ?>
				<?php $j++; ?>
				<?php if ($j == ($columns+1)) $j = 1; ?>
			<?php endforeach; ?>
		</div>
		<?php $i++; ?>
		<?php endwhile; ?>
	<?php else: ?>
	<?php esc_html_e("No items in this taxonomy yet", "WCSEARCH"); ?>
	<?php endif; ?>
	</div>
</div>
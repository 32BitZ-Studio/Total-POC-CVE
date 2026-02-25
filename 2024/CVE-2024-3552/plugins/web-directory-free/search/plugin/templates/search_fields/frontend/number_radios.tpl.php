<div class="wcsearch-search-input wcsearch-search-input-radios <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-input-terms-columns wcsearch-search-model-input-radios-wrapper">
	<?php
	if ($min_max_options): 
		$i = 1;
		while ($i <= ($columns+1)): ?>
		<div class="wcsearch-search-input-terms-column wcsearch-search-input-terms-column-<?php echo esc_attr($columns); ?>">
			<?php $j = 1; ?>
			<?php foreach (wcsearch_get_number_labels($min_max_options, $used_by, $slug) AS $option_label=>$option_value): ?>
			<?php if ($i == $j): ?>
				<div class="wcsearch-radio">
					<label>
						<input type="radio" name="<?php echo esc_attr($slug); ?>" value="<?php echo esc_attr($option_value); ?>" <?php if ($values == $option_value)  echo 'checked'; ?> />
						<?php echo wcsearch_number_option_label($option_label); ?><?php if ($counter): ?> (<?php echo wcsearch_get_count(array('price' => $option_value, 'used_by' => $used_by)); ?>)<?php endif; ?>
					</label>
				</div>
			<?php endif; ?>
			<?php $j++; ?>
			<?php if ($j == ($columns+1)) $j = 1; ?>
			<?php endforeach; ?>
		</div>
		<?php $i++; ?>
		<?php endwhile; ?>
	<?php endif; ?>
	</div>
</div>
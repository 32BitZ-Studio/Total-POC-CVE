<div class="wcsearch-search-input wcsearch-search-input-ratings <?php echo $search_model->openedClosedClass(); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-input-label"><?php echo esc_html($title); ?></label>
	<?php
	if ($options): ?>
	<?php
	$values = explode(',', $values);
	?>
	<div class="wcsearch-search-input-terms-column">
		<?php foreach ($options AS $option_value=>$option_label): ?>
		<div class="wcsearch-rating-checkbox-wrapper">
			<div class="wcsearch-rating-checkbox">
				<div class="wcsearch-checkbox">
					<label>
						<input type="checkbox" name="ratings" value="<?php echo esc_attr($option_value); ?>" <?php if (in_array($option_value, $values))  echo 'checked'; ?> />
						<?php echo esc_html($option_label); ?>
					</label>
				</div>
			</div>
			<?php wcsearch_render_avg_rating($option_value, $stars_color); ?><?php if ($counter): ?> (<?php echo wcsearch_get_count(array('ratings' => $option_value, 'used_by' => $used_by)); ?>)<?php endif; ?>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</div>
<script>
(function($) {
	"use strict";
	
	window.wcsearch_callback_ratings_stars_color_<?php echo esc_attr($search_model->id); ?> = function(color_input, params) {
		var styles = '#<?php echo esc_attr($search_model->id); ?> label.wcsearch-rating-icon { color: '+color_input+' !important; }';
		$("head").append('<style>'+styles+'</style>');

		$("#<?php echo esc_attr($search_model->id); ?>.wcsearch-search-model-input-ratings").data("stars_color", color_input);
		wcsearch_model_update_placeholders();
	}
})(jQuery);
</script>
<div class="wcsearch-search-model-input wcsearch-search-model-input-ratings" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<?php
	if ($options): ?>
	<?php
	$values = explode(',', $values);
	?>
	<div class="wcsearch-search-model-input-terms-column">
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
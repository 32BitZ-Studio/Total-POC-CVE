<script>
(function($) {
	"use strict";
	
	window.wcsearch_callback_tax_color_<?php echo esc_attr($search_model->id); ?> = function(color_input, params) {
		if (typeof params.term_id != "undefined") {
			var input = $("#<?php echo esc_attr($search_model->id); ?>");
			
			if (color_input) {
				var styles = '#<?php echo esc_attr($search_model->id); ?> .wcsearch-term-id-'+params.term_id+' .wcsearch-control-indicator { background-color: '+color_input+' !important; }';
				
				var tick_color = '#FFFFFF';
				if (wcsearch_get_luma_color(color_input) > 205) {
					var tick_color = '#757575';
				}
				styles += '#<?php echo esc_attr($search_model->id); ?> .wcsearch-term-id-'+params.term_id+' .wcsearch-control-indicator::after { color: '+tick_color+' !important; }';
				styles += '#<?php echo esc_attr($search_model->id); ?> .wcsearch-radio.wcsearch-term-id-'+params.term_id+' .wcsearch-control-indicator::after { background-color: '+tick_color+' !important; }';
				
				$(input).append('<style data-term-id="'+params.term_id+'">'+styles+'</style>');

				var options = { 'color': color_input };
				wcsearch_set_term_options(input, params.term_id, options);
			} else {
				$("style[data-term-id='"+params.term_id+"']").remove();

				wcsearch_unset_term_options(input, params.term_id, 'color');
			}

			wcsearch_model_update_placeholders();
		}
	}
})(jQuery);
</script>

<?php
if (!empty($terms_options)) :
foreach ($selection_items AS $key=>$item):
	if ($color = wcsearch_get_term_option($terms_options, $item->term_id, 'color')): ?>
	<style data-term-id="<?php echo esc_attr($item->term_id); ?>">
	#<?php echo esc_attr($search_model->id); ?> .wcsearch-term-id-<?php echo esc_attr($item->term_id); ?> .wcsearch-control-indicator { background-color: <?php echo esc_attr($color); ?> !important; }
	<?php if (wcsearch_get_luma_color($color) > 205) { $tick_color = '#757575'; } else { $tick_color = '#FFFFFF'; }
	#<?php echo esc_attr($search_model->id); ?> .wcsearch-term-id-<?php echo esc_attr($item->term_id); ?> .wcsearch-control-indicator::after { color: <?php echo esc_attr($tick_color); ?> !important; }
	#<?php echo esc_attr($search_model->id); ?> .wcsearch-radio.wcsearch-term-id-<?php echo esc_attr($item->term_id); ?> .wcsearch-control-indicator::after { background-color: <?php echo esc_attr($tick_color); ?> !important; }
	<?php endif; ?>
	</style>
<?php
endforeach;
endif; ?>

<div class="wcsearch-search-model-input wcsearch-search-model-input-<?php echo esc_attr($mode); ?>" <?php echo $search_model->getOptionsString(); ?>>
	<label class="wcsearch-search-model-input-label"><?php echo esc_html($title); ?></label>
	<div class="wcsearch-search-model-input-terms-columns" <?php if ($height_limit): ?>style="height: <?php echo $height_limit; ?>px;"<?php endif; ?>>
	<?php
	if ($selection_items):
		$i = 1;
		while ($i <= $columns): ?>
		<div class="wcsearch-search-model-input-terms-column wcsearch-search-model-input-<?php echo esc_attr($mode); ?>-column wcsearch-search-model-input-terms-column-<?php echo esc_attr($columns); ?> wcsearch-search-model-input-<?php echo esc_attr($mode); ?>-column-<?php echo esc_attr($columns); ?>">
			<?php $j = 1; ?>
			<?php foreach ($selection_items AS $key=>$item): ?>
				<?php if ($i == $j): ?>
				<div class="<?php if ($mode =='checkboxes'): ?>wcsearch-checkbox<?php elseif ($mode =='radios'): ?>wcsearch-radio<?php endif; ?> wcsearch-term-wrapper wcsearch-term-id-<?php echo esc_attr($item->term_id); ?>">
					<label>
					<?php if ($mode =='checkboxes'): ?>
						<input type="checkbox" name="<?php echo esc_attr($tax); ?>" value="<?php echo esc_attr($item->term_id); ?>" <?php if ($values && in_array($item->term_id, explode(',', $values)))  echo 'checked'; ?> />
					<?php elseif ($mode =='radios'): ?>
						<input type="radio" name="<?php echo esc_attr($tax); ?>" value="<?php echo esc_attr($item->term_id); ?>" <?php if ($values && in_array($item->term_id, explode(',', $values)))  echo 'checked'; ?> />
					<?php endif; ?>
					<?php echo esc_html($item->name); ?><?php if ($counter): echo ' ('.wcsearch_get_count(array('mode' => $mode, 'term' => $item, 'used_by' => $used_by)).')'; endif; ?>
					</label>
					<a class="wcsearch-model-options-link" data-term-id="<?php echo esc_attr($item->term_id); ?>" data-term-name="<?php echo esc_attr($item->name); ?>" title="<?php esc_attr_e("Edit color", "WCSEARCH"); ?>"><?php esc_html_e("options", "WCSEARCH"); ?></a>
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
<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Configure select/radio buttons field', 'W2DC'); ?>
</h2>

<script>
	(function($) {
		"use strict";
	
		$(function() {
			var max_index = <?php echo ((count(array_keys($content_field->selection_items)) ? max(array_keys($content_field->selection_items)) : 1)); ?>;
			$('body').on('click', "#add_selection_item", function() {
				max_index = max_index+1;
				$("#w2dc-selection-items-wrapper").append('<div class="selection_item"><input name="selection_items['+max_index+']" type="text" class="regular-text" value="" /><img class="w2dc-delete-selection-item" src="<?php echo W2DC_RESOURCES_URL . 'images/delete.png'?>" title="<?php esc_attr_e('Remove selection item', 'W2DC')?>" /> <span class="w2dc-move-label"><?php esc_attr_e('move', 'W2DC'); ?></span><?php echo esc_js('(ID: ', 'W2DC'); ?>'+max_index+')</div>');
			});
			$(document).on("click", ".w2dc-delete-selection-item", function() {
				$(this).parent().remove();
			});

			$("#w2dc-selection-items-wrapper").sortable({
				delay: 50,
				placeholder: "ui-sortable-placeholder",
				helper: function(e, ui) {
					ui.children().each(function() {
						$(this).width($(this).width());
					});
					return ui;
				},
				start: function(e, ui){
					ui.placeholder.height(ui.item.height());
				}
	    	});
		});
	})(jQuery);
</script>

<?php _e('You may order items by drag & drop.', 'W2DC'); ?>
<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_configure_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<?php do_action('w2dc_select_content_field_configuration_html', $content_field); ?>
			<tr>
				<th scope="row">
					<label><?php _e('Selection items:', 'W2DC'); ?></label>
				</th>
				<td>
					<div id="w2dc-selection-items-wrapper">
						<?php if (count($content_field->selection_items)): ?>
						<?php foreach ($content_field->selection_items AS $key=>$item): ?>
						<div class="selection_item">
							<input
								name="selection_items[<?php echo $key; ?>]"
								type="text"
								class="regular-text"
								value="<?php echo esc_attr($item); ?>" />
							<img class="w2dc-delete-selection-item" src="<?php echo W2DC_RESOURCES_URL . 'images/delete.png'?>" title="<?php esc_attr_e('Remove selection item', 'W2DC')?>" />
							<span class="w2dc-move-label"><?php _e('move', 'W2DC'); ?></span>
							<?php printf(__('(ID: %d)', 'W2DC'), $key); ?>
						</div>
						<?php endforeach; ?>
						<?php else: ?>
						<div class="selection_item">
							<input
								name="selection_items[1]"
								type="text"
								class="regular-text"
								value="" />
							<img class="w2dc-delete-selection-item" src="<?php echo W2DC_RESOURCES_URL . 'images/delete.png'?>" title="<?php esc_attr_e('Remove selection item', 'W2DC')?>" />
							<span class="w2dc-move-label"><?php _e('move', 'W2DC'); ?></span>
							<?php printf(__('(ID: %d)', 'W2DC'), 1); ?>
						</div>
						<?php endif; ?>
					</div>
				</td>
			</tr>
		</tbody>
	</table>
	<input type="button" id="add_selection_item" class="button button-primary" value="<?php esc_attr_e('Add selection item', 'W2DC'); ?>" />
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
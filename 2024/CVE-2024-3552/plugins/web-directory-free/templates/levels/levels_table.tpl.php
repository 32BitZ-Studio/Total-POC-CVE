<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<script>
	(function($) {
	"use strict";

		$(function() {
			$("#the-list").sortable({
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
				},
				update: function( event, ui ) {
					$("#levels_order").val($(".level_weight_id").map(function() {
						return $(this).val();
					}).get());
				}
		    }).disableSelection();
		});
	})(jQuery);
</script>

<h2>
	<?php _e('Listings levels', 'W2DC'); ?>
	<?php echo sprintf('<a class="add-new-h2" href="?page=%s&action=%s">' . __('Create new level', 'W2DC') . '</a>', $_GET['page'], 'add'); ?>
</h2>

<?php _e('You may order listings levels by drag & drop rows in the table.', 'W2DC'); ?>

<form method="POST" action="<?php echo admin_url('admin.php?page=w2dc_levels'); ?>">
	<input type="hidden" id="levels_order" name="levels_order" value="" />
	<?php 
		$levels_table->display();
		
		submit_button(__('Save order', 'W2DC'));
	?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
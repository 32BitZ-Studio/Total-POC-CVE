<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2><?php _e('CSV Import'); ?></h2>

<p class="description"><?php _e('On this first step select CSV file for import, also you may import images in zip archive', 'W2DC'); ?></p>

<script>
	(function($) {
		"use strict";

		$(function() {
			$("#import_button").on("click", function(e) {
				if (confirm('Please, make backup of whole wordpress database before import.'))
					$("#import_form").trigger('click');
				else
					e.preventDefault();
			});
		});
	})(jQuery);
</script>
<form method="POST" action="" id="import_form" enctype="multipart/form-data">
	<input type="hidden" name="action" value="import_settings">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_csv_import_nonce');?>
	
	<h3><?php _e('Import settings', 'W2DC'); ?></h3>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Import type', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<label>
						<input
							name="import_type"
							type="radio"
							value="create_listings"
							checked />
						<?php _e('create new listings', 'W2DC'); ?>
					</label>

					<br />

					<label>
						<input
							name="import_type"
							type="radio"
							value="update_listings" />
						<?php _e('update existing listings (post ID column required)', 'W2DC'); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('CSV File', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="csv_file"
						type="file" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Images ZIP archive', 'W2DC'); ?>
				</th>
				<td>
					<input
						name="images_file"
						type="file" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Columns separator', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="columns_separator"
						type="text"
						size="2"
						value="<?php echo isset($columns_separator) ? esc_attr($columns_separator) : ','; ?>" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Categories, Locations, Tags, Images, MultiValues separator', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="values_separator"
						type="text"
						size="2"
						value="<?php echo isset($values_separator) ? esc_attr($values_separator) : ';'; ?>" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php w2dc_renderTemplate('csv_manager/import_instructions.tpl.php'); ?>
	
	<?php submit_button(__('Upload', 'W2DC'), 'primary', 'submit', true, array('id' => 'import_button')); ?>
</form>

<?php if (w2dc_getValue($_GET, 'geocode_locations')): ?>
<form method="POST" action="">
	<input type="hidden" name="action" value="geocode_locations">
	
	<?php submit_button(__('Geocode locations', 'W2DC'), 'primary w2dc-csv-geocode-locations', 'geocode_locations'); ?>
</form>
<?php endif; ?>

<h2><?php _e('CSV Export'); ?></h2>

<p class="description"><?php _e('Enter offset of items to start with. Enter 0 to start from the beginning. It will export entered number of items. Reduce the number of items if you get timeout message.', 'W2DC'); ?></p>

<form method="POST" action="">
	<input type="hidden" name="action" value="export_settings">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_csv_import_nonce');?>
	
	<table class="form-table">
		<tbody>
			<input type="hidden" name="export_type" value="export_listings" />
			<tr>
				<th scope="row">
					<?php _e('Items number', 'W2DC'); ?>
				</th>
				<td>
					<input
						name="number"
						type="text"
						value="1000" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<?php _e('Items offset', 'W2DC'); ?>
				</th>
				<td>
					<input
						name="offset"
						type="text"
						value="0" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(__('Export', 'W2DC'), 'primary', 'csv_export'); ?>
	<?php submit_button(__('Download Images', 'W2DC'), 'primary', 'export_images'); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
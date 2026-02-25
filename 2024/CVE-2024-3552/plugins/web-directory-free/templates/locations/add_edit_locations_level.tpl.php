<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php
	if ($locations_level_id)
		_e('Edit locations level', 'W2DC');
	else
		_e('Create new locations level', 'W2DC');
	?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_locations_levels_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Level name', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="name"
						type="text"
						class="regular-text"
						value="<?php echo $locations_level->name; ?>" />
					<?php w2dc_wpmlTranslationCompleteNotice(); ?>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('In address line', 'W2DC'); ?></label>
				</th>
				<td>
					<input type="checkbox" value="1" name="in_address_line" <?php if ($locations_level->in_address_line) echo 'checked'; ?> />
					<p class="description"><?php _e("Render locations of this level in address line", 'W2DC'); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Allow add term', 'W2DC'); ?></label>
				</th>
				<td>
					<input type="checkbox" value="1" name="allow_add_term" <?php if ($locations_level->allow_add_term) echo 'checked'; ?> />
					<p class="description"><?php _e("Users able to add new location from the frontend", 'W2DC'); ?></p>
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php
	if ($locations_level_id)
		submit_button(__('Save changes', 'W2DC'));
	else
		submit_button(__('Create locations level', 'W2DC'));
	?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
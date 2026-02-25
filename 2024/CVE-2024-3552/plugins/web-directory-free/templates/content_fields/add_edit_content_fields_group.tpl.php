<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php
	if ($group_id)
		_e('Edit content fields group', 'W2DC');
	else
		_e('Create new content fields group', 'W2DC');
	?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Fields Group name', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="name"
						id="content_fields_group_name"
						type="text"
						class="regular-text"
						value="<?php echo esc_attr($content_fields_group->name); ?>" />
						<?php w2dc_wpmlTranslationCompleteNotice(); ?>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('On tab', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="on_tab"
						type="checkbox"
						value="1"
						<?php checked($content_fields_group->on_tab); ?> />
					<p class="description"><?php _e("Place this group on separate tab on single listings pages", 'W2DC'); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Hide from anonymous users', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="hide_anonymous"
						type="checkbox"
						value="1"
						<?php checked($content_fields_group->hide_anonymous); ?> />
					<p class="description"><?php _e("This group of fields will be shown only for registered users", 'W2DC'); ?></p>
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php
	if ($group_id)
		submit_button(__('Save changes', 'W2DC'));
	else
		submit_button(__('Create content fields group', 'W2DC'));
	?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
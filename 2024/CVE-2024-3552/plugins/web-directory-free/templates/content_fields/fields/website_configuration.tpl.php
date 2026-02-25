<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Configure website field', 'W2DC'); ?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_configure_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Open link in new window', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="is_blank"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->is_blank) echo 'checked'; ?>/>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Add nofollow attribute', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="is_nofollow"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->is_nofollow) echo 'checked'; ?>/>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Enable link text field', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="use_link_text"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->use_link_text) echo 'checked'; ?> />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Use placeholder link text when empty', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="use_default_link_text"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->use_default_link_text) echo 'checked'; ?> />
						<p class="description"><?php _e('In other case the URL will be displayed as link text'); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Placeholder link text', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="default_link_text"
						type="text"
						class="regular-text"
						value="<?php echo esc_attr($content_field->default_link_text); ?>" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
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
					<label><?php _e('Enable file title field', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="use_text"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->use_text) echo 'checked'; ?> />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Use default file title text when empty', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="use_default_text"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->use_default_text) echo 'checked'; ?> />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Default file title text', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="default_text"
						type="text"
						class="regular-text"
						value="<?php echo esc_attr($content_field->default_text); ?>" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Allowed file types', 'W2DC'); ?></label>
				</th>
				<td>
					<?php foreach ($content_field->get_mime_types() AS $type=>$label): ?>
					<label>
						<input
							name="allowed_mime_types[]"
							type="checkbox"
							class="regular-text"
							value="<?php echo $type; ?>"
							<?php if (in_array($type, $content_field->allowed_mime_types)) echo 'checked'; ?> /> <?php echo esc_html($label['label']); ?> (<?php echo esc_html($type); ?>) <br />
					</label>
					<?php endforeach; ?>
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
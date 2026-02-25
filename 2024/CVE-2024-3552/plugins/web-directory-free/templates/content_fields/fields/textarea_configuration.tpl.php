<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Configure textarea field', 'W2DC'); ?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_configure_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Max length', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="max_length"
						type="text"
						size="8"
						value="<?php echo esc_attr($content_field->max_length); ?>" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('HTML editor enabled', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="html_editor"
						type="checkbox"
						value="1"
						<?php checked(1, $content_field->html_editor, true)?> />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Run shortcodes', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="do_shortcodes"
						type="checkbox"
						value="1"
						<?php checked(1, $content_field->do_shortcodes, true)?> />
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Configure number field', 'W2DC'); ?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_configure_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Is integer or decimal', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="is_integer"
						type="radio"
						value="1"
						<?php if($content_field->is_integer) echo 'checked'; ?> />
					<?php _e('integer', 'W2DC')?>
					&nbsp;&nbsp;
					<input
						name="is_integer"
						type="radio"
						value="0"
						<?php if(!$content_field->is_integer) echo 'checked'; ?> />
					<?php _e('decimal', 'W2DC')?>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Decimal separator', 'W2DC'); ?></label>
				</th>
				<td>
					<select name="decimal_separator">
						<option value="." <?php if($content_field->decimal_separator == '.') echo 'selected'; ?>><?php _e('dot', 'W2DC')?></option>
						<option value="," <?php if($content_field->decimal_separator == ',') echo 'selected'; ?>><?php _e('comma', 'W2DC')?></option>
					</select>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Thousands separator', 'W2DC'); ?></label>
				</th>
				<td>
					<select name="thousands_separator">
						<option value="" <?php if($content_field->thousands_separator == '') echo 'selected'; ?>><?php _e('no separator', 'W2DC')?></option>
						<option value="." <?php if($content_field->thousands_separator == '.') echo 'selected'; ?>><?php _e('dot', 'W2DC')?></option>
						<option value="," <?php if($content_field->thousands_separator == ',') echo 'selected'; ?>><?php _e('comma', 'W2DC')?></option>
						<option value=" " <?php if($content_field->thousands_separator == ' ') echo 'selected'; ?>><?php _e('space', 'W2DC')?></option>
					</select>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Min', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="min"
						type="text"
						size="2"
						value="<?php echo esc_attr($content_field->min); ?>" />
					<p class="description"><?php _e("leave empty if you do not need to limit this field", 'W2DC'); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Max', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="max"
						type="text"
						size="2"
						value="<?php echo esc_attr($content_field->max); ?>" />
					<p class="description"><?php _e("leave empty if you do not need to limit this field", 'W2DC'); ?></p>
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
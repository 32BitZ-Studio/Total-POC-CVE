<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Configure price field', 'W2DC'); ?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_configure_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Currency symbol', 'W2DC'); ?><span class="w2dc-red-asterisk">*</span></label>
				</th>
				<td>
					<input
						name="currency_symbol"
						type="text"
						size="1"
						value="<?php echo esc_attr($content_field->currency_symbol); ?>" />
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Currency symbol position', 'W2DC'); ?></label>
				</th>
				<td>
					<select name="symbol_position">
						<option value="1" <?php if($content_field->symbol_position == '1') echo 'selected'; ?>>$1.00</option>
						<option value="2" <?php if($content_field->symbol_position == '2') echo 'selected'; ?>>$ 1.00</option>
						<option value="3" <?php if($content_field->symbol_position == '3') echo 'selected'; ?>>1.00$</option>
						<option value="4" <?php if($content_field->symbol_position == '4') echo 'selected'; ?>>1.00 $</option>
					</select>
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
					<label><?php _e('Hide decimals', 'W2DC'); ?></label>
				</th>
				<td>
					<select name="hide_decimals">
						<option value="0" <?php if($content_field->hide_decimals == '0') echo 'selected'; ?>><?php _e('no', 'W2DC')?></option>
						<option value="1" <?php if($content_field->hide_decimals == '1') echo 'selected'; ?>><?php _e('yes', 'W2DC')?></option>
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
		</tbody>
	</table>
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
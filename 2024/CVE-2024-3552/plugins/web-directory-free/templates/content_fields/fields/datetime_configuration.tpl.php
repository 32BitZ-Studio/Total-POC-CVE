<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Configure date-time field', 'W2DC'); ?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_configure_content_fields_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php _e('Enable time in field', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="is_time"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->is_time) echo 'checked'; ?>/>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label><?php _e('Hide listings with passed dates', 'W2DC'); ?></label>
				</th>
				<td>
					<input
						name="hide_past_dates"
						type="checkbox"
						class="regular-text"
						value="1"
						<?php if($content_field->hide_past_dates) echo 'checked'; ?>/>
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(__('Save changes', 'W2DC')); ?>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
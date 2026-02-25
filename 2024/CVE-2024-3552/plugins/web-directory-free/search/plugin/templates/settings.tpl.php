<?php wcsearch_renderTemplate('admin_header.tpl.php'); ?>

<h2><?php esc_html_e('Search Settings', 'WCSEARCH'); ?>
</h2>

<form method="POST" action="">
	<?php wp_nonce_field(WCSEARCH_PATH, 'wcsearch_settings_nonce');?>
	<table class="form-table">
		<tbody>
			<tr>
				<th scope="row">
					<label><?php esc_html_e('Purchase code', 'WCSEARCH'); ?><span class="wcsearch-red-asterisk">*</span></label>
					<p>You should receive purchase (license) code after purchase <div class="w2dc-license-support-checker" data-nonce="<?php echo wp_create_nonce('w2dc_license_support_checker_nonce'); ?>"></div></p>
				</th>
				<td>
					<input
						name="wcsearch_purchase_code"
						id="wcsearch_purchase_code"
						type="text"
						class="regular-text"
						value="<?php echo get_option("wcsearch_purchase_code"); ?>" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<?php submit_button(esc_html__('Save changes', 'WCSEARCH')); ?>
</form>

<?php wcsearch_renderTemplate('admin_footer.tpl.php'); ?>
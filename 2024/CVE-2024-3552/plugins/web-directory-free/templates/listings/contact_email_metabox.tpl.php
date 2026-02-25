<p><?php _e("When field is empty contact messages from contact form will be sent directly to author email.", 'W2DC'); ?></p>

<div class="w2dc-content">
	<input class="w2dc-field-input-string w2dc-form-control" type="text" name="contact_email" value="<?php echo esc_attr($listing->contact_email); ?>" />
</div>
	
<?php do_action('w2dc_contact_email_metabox_html', $listing); ?>
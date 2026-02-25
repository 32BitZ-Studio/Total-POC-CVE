<form method="POST" action="">
	<input type="hidden" name="action" value="import_settings">
	<input type="hidden" name="import_type" value="<?php echo esc_attr($import_type); ?>">
	<input type="hidden" name="csv_file_name" value="<?php echo esc_attr($csv_file_name); ?>">
	<input type="hidden" name="images_dir" value="<?php echo esc_attr($images_dir); ?>">
	<input type="hidden" name="columns_separator" value="<?php echo esc_attr($columns_separator); ?>">
	<input type="hidden" name="values_separator" value="<?php echo esc_attr($values_separator); ?>">
	<input type="hidden" name="author" value="<?php echo esc_attr($author); ?>">
	<?php if ($import_type == 'create_listings' || $import_type == 'update_listings'): ?>
	<input type="hidden" name="if_term_not_found" value="<?php echo esc_attr($if_term_not_found); ?>">
	<input type="hidden" name="do_geocode" value="<?php echo esc_attr($do_geocode); ?>">
	<?php if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')): ?>
	<input type="hidden" name="is_claimable" value="<?php echo esc_attr($is_claimable); ?>">
	<?php endif; ?>
	<?php endif; ?>
	<?php foreach ($fields AS $field): ?>
	<input type="hidden" name="fields[]" value="<?php echo esc_attr($field); ?>">
	<?php endforeach; ?>
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_csv_import_nonce');?>

	<?php if ($log['errors'] || $test_mode): ?>
	<?php submit_button(__('Go back', 'W2DC'), 'primary', 'goback', false); ?>
	&nbsp;&nbsp;&nbsp;
	<?php endif; ?>

	<a href="<?php echo admin_url('admin.php?page=w2dc_csv_import'); ?>" class="button button-primary"><?php _e('Import new file', 'W2DC'); ?></a>
</form>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
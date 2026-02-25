<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2><?php _e('Demo Data Import'); ?></h2>

<?php if (!w2dc_getValue($_POST, 'submit')): ?>
<div class="error">
	<p><?php _e("1. This is Demo Data Import tool. This tool will help you to install some demo content, such as listings, search forms, custom home pages and pages with examples of the shortcodes usage.", "W2DC"); ?></p>
	<p><?php _e("2. Each time you click import button - it creates new set of listings and pages. Avoid duplicates.", "W2DC"); ?></p>
	<p><?php _e("3. Import will not add pages in your navigation menus.", "W2DC"); ?></p>
	<p><?php _e("4. This is not 100% copy of the demo site. Just gives some examples of the shortcodes usage. Final view and layout depends on your theme options.", "W2DC"); ?></p>
	<p><?php _e("5. Web 2.0 Directory page with [webdirectory] shortcode is mandatory. Listing Single Template page quite recommended [webdirectory-listing-page]. Others you can delete.", "W2DC"); ?></p>
</div>

<form method="POST" action="" id="demo_data_import_form">
	<?php wp_nonce_field(W2DC_PATH, 'w2dc_csv_import_nonce');?>
	
	<?php submit_button(__('Start import', 'W2DC'), 'primary', 'submit', true, array('id' => 'import_button')); ?>
	
	<?php
	if (w2dc_getValue($_GET, "export")) {
		submit_button(__('Export', 'W2DC'), 'primary', 'export', true, array('id' => 'export_button'));
	}
	?>
</form>
<?php endif; ?>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
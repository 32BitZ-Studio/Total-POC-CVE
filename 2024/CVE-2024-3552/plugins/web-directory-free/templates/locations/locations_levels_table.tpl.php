<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Locations levels', 'W2DC'); ?>
	<?php echo sprintf('<a class="add-new-h2" href="?page=%s&action=%s">' . __('Create new locations level', 'W2DC') . '</a>', $_GET['page'], 'add'); ?>
</h2>

<?php $locations_levels_table->display(); ?>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
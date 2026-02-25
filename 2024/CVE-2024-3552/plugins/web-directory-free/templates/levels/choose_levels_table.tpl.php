<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Choose level for new listing', 'W2DC'); ?>
</h2>

<?php if ($levels_count == 0): ?>
<p><?php echo sprintf(__('Before listings creation you must have at least one listings level, please create new level <a href="%s">here</a>', 'W2DC'), admin_url('admin.php?page=w2dc_levels&action=add')); ?></p>
<?php endif; ?>

<?php 
	$levels_table->display();
?>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
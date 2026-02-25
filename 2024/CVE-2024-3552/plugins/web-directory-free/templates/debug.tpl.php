<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php _e('Directory Debug', 'W2DC'); ?>
</h2>

<textarea style="width: 100%; height: 700px">
geolocation response = <?php var_dump($geolocation_response); ?>


<?php var_dump($w2dc_instance->updater); ?>
<?php if (isset($w2dc_instance->updater)): ?>
license keys = <?php $w2dc_instance->updater->getDownload_url(true); ?>
<?php endif; ?>

SERVER_ADDR IP = <?php echo $_SERVER['SERVER_ADDR']; ?>


$w2dc_instance->index_pages_all = <?php var_dump($w2dc_instance->index_pages_all); ?>

$w2dc_instance->listing_pages_all = <?php var_dump($w2dc_instance->listing_pages_all); ?>

<?php if (isset($w2dc_instance->submit_pages_all)): ?>
$w2dc_instance->submit_pages_all = <?php var_dump($w2dc_instance->submit_pages_all); ?>
<?php endif; ?>

<?php if (isset($w2dc_instance->dashboard_page_id)): ?>
$w2dc_instance->dashboard_page_id = <?php echo $w2dc_instance->dashboard_page_id; ?>
<?php endif; ?>

<?php
if ($rewrite_rules):
foreach ($rewrite_rules AS $key=>$rule)
echo $key . '
' . $rule . '

';
endif;
?>

image_sizes = <?php var_dump(w2dc_get_registered_image_sizes()); ?>

<?php foreach ($settings AS $setting)
echo $setting['option_name'] . ' = ' . $setting['option_value'] . '

';
?>


<?php var_dump($levels); ?>


<?php var_dump($content_fields); ?>
</textarea>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
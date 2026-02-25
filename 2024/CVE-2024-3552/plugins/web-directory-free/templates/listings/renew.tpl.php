<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php echo apply_filters('w2dc_renew_option', __('Renew listing', 'W2DC'), $listing); ?>
</h2>

<p><?php _e('Listing will be renewed and raised up to the top of all lists, those ordered by date.', 'W2DC'); ?></p>

<?php do_action('w2dc_renew_html', $listing); ?>

<?php if ($action == 'show'): ?>
<a href="<?php echo admin_url('options.php?page=w2dc_renew&listing_id=' . $listing->post->ID . '&renew_action=renew&referer=' . urlencode($referer)); ?>" class="button button-primary"><?php _e('Renew listing', 'W2DC'); ?></a>
&nbsp;&nbsp;&nbsp;
<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Cancel', 'W2DC'); ?></a>
<?php elseif ($action == 'renew'): ?>
<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Go back ', 'W2DC'); ?></a>
<?php endif; ?>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
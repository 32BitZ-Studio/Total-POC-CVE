<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php echo apply_filters('w2dc_raiseup_option', sprintf(__('Raise up listing "%s"', 'W2DC'), $listing->title()), $listing); ?>
</h2>

<p><?php _e('Listing will be raised up to the top of all lists, those ordered by date.', 'W2DC'); ?></p>
<p><?php _e('Note, that listing will not stick on top, so new listings and other listings, those were raised up later, will place higher.', 'W2DC'); ?></p>

<?php do_action('w2dc_raise_up_html', $listing); ?>

<?php if ($action == 'show'): ?>
<a href="<?php echo admin_url('options.php?page=w2dc_raise_up&listing_id=' . $listing->post->ID . '&raiseup_action=raiseup&referer=' . urlencode($referer)); ?>" class="button button-primary"><?php _e('Raise up', 'W2DC'); ?></a>
&nbsp;&nbsp;&nbsp;
<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Cancel', 'W2DC'); ?></a>
<?php elseif ($action == 'raiseup'): ?>
<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Go back ', 'W2DC'); ?></a>
<?php endif; ?>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
<?php w2dc_renderTemplate('admin_header.tpl.php'); ?>

<h2>
	<?php printf(__('Approve or decline claim of listing "%s"', 'W2DC'), $listing->title()); ?>
</h2>

<?php if ($action == 'show'): ?>
<p><?php printf(__('User "%s" had claimed this listing.', 'W2DC'), $listing->claim->claimer->display_name); ?></p>
<?php if ($listing->claim->claimer_message): ?>
<p><?php _e('Message from claimer:', 'W2DC'); ?><br /><i><?php echo $listing->claim->claimer_message; ?></i></p>
<?php endif; ?>
<p><?php _e('Claimer will receive email notification.', 'W2DC'); ?></p>

<a href="<?php echo admin_url('options.php?page=w2dc_process_claim&listing_id=' . $listing->post->ID . '&claim_action=approve&referer=' . urlencode($referer)); ?>" class="button button-primary"><?php _e('Approve', 'W2DC'); ?></a>
&nbsp;&nbsp;&nbsp;
<a href="<?php echo admin_url('options.php?page=w2dc_process_claim&listing_id=' . $listing->post->ID . '&claim_action=decline&referer=' . urlencode($referer)); ?>" class="button button-primary"><?php _e('Decline', 'W2DC'); ?></a>
&nbsp;&nbsp;&nbsp;
<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Cancel', 'W2DC'); ?></a>
<?php elseif ($action == 'processed'): ?>
<a href="<?php echo $referer; ?>" class="button button-primary"><?php _e('Go back ', 'W2DC'); ?></a>
<?php endif; ?>

<?php w2dc_renderTemplate('admin_footer.tpl.php'); ?>
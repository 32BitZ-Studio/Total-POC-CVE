<?php

/**
 * Our comments form template, the comments loop is loaded via AJAX from w2dc_comments_load_template()
 */
if ( !defined( 'ABSPATH' ) ) die( 'You cannot access this template file directly' );

// Get current listing
$listing = w2dc_isListing();

?>
<?php
    $name = __('Name...', 'W2DC');
    $email = __('Email...', 'W2DC');
    $website = __('Website...', 'W2DC');
    $user_email = null;
    $user_website = null;
    $user_name = null;

    if ( is_user_logged_in() ){
        $current_user = wp_get_current_user();
        $user_name = $current_user->user_nicename;
        $user_email = $current_user->user_email;
        $user_website = $current_user->user_url;
    }
?>
<div class="w2dc-comments-container" name="comments">
	<div id="w2dc_comments_ajax_handle" class="last-child" data-post_id="<?php echo $listing->post->ID; ?>">
		<div id="w2dc_comments_ajax_target" style="display: none;"></div>
		<input type="hidden" name="comment_parent" value="0" id="comment_parent" />
		<input type="hidden" name="w2dc_comments_nonce" value="<?php print wp_create_nonce('w2dc_comments_nonce'); ?>" id="w2dc_comments_nonce" />
		<?php if ( get_option('comment_registration') != 1 || is_user_logged_in() ) : ?>
			<div class="w2dc-comments-content-form w2dc-comments-content-comment-fields">
				<div class="w2dc-comments-p">
					<h4 id="w2dc-comments-leave-comment-label"><?php _e('Leave a comment', 'W2DC'); ?></h4>
					<form action="javascript://" method="POST" id="w2dc_default_add_comment_form">
						<input type="hidden" name="w2dc_comments_nonce" value="<?php print wp_create_nonce('w2dc_comments_nonce'); ?>" id="w2dc_comments_nonce" />
						<?php w2dc_comments_profile_pic(); ?>
						<textarea placeholder="<?php esc_attr_e('Press enter to submit comment...', 'W2DC'); ?>" tabindex="4" id="comment" name="comment" id="w2dc-comments-textarea" class="w2dc-comments-auto-expand submit-on-enter"></textarea>
						<span class="w2dc-comments-more-handle"><a href="#"><?php _e('more', 'W2DC'); ?></a></span>
						<div class="w2dc-comments-more-container" <?php if ($user_email != null) : ?>style="display: none;"<?php endif; ?>>
							<div class="w2dc-comments-allowed-tags-container">
								<?php printf(__('Allowed %s tags and attributes:', 'W2DC'), '<abbr title="HyperText Markup Language">HTML</abbr>'); ?>
								<code>&lt;a href="" title=""&gt; &lt;blockquote&gt; &lt;code&gt; &lt;em&gt; &lt;strong&gt;</code>
							</div>
							<div class="w2dc-comments-field"><input type="text" tabindex="5" name="user_name" id="w2dc_comments_user_name" placeholder="<?php print $name; ?>" value="<?php print $user_name; ?>"  /></div>
							<div class="w2dc-comments-field"><input type="email" required tabindex="5" name="user_email" id="w2dc_comments_user_email" placeholder="<?php print $email; ?>" value="<?php print $user_email; ?>"  /></div>
							<div class="w2dc-comments-field"><input type="url" required tabindex="6" name="user_url" id="w2dc_comments_user_url" placeholder="<?php print $website; ?>" value="<?php print $user_website; ?>" /></div>
						</div>
					</form>
				</div>
			</div>
		<?php else : ?>
			<div class="callout-container">
				<p><?php printf(__('Please %s or %s to leave Comments', 'W2DC'), wp_register('','', false), '<a href="' . wp_login_url() . '" class="w2dc-comments-login-handle">' . __('Login', 'W2DC') . '</a>'); ?></p>
			</div>
		<?php endif; ?>
	</div>
</div>
<?php 

class w2dc_comments_manager {
	
	public function __construct() {
		add_action('wp_ajax_w2dc_comments_add_comment', array($this, 'comments_add_comment'));
	    add_action('wp_ajax_nopriv_w2dc_comments_add_comment', array($this, 'comments_add_comment'));
	    add_action('wp_ajax_w2dc_comments_load_template', array($this, 'comments_load_template'));
	    add_action('wp_ajax_nopriv_w2dc_comments_load_template', array($this, 'comments_load_template'));
	}

	public function comments_load_template() {
		check_ajax_referer('w2dc_comments_nonce', 'security');

		$this->display_comments_node($_POST['post_id']);
	    
	    die();
	}
	
	public function display_comments_node($post_id, $parent = '') {
		$comments = get_comments(array(
				'post_id' => (int)$post_id,
				'number'  => 100,
				'status'  => 'approve',
				'order'   => 'ASC',
				'parent'  => (int)$parent
		));

		if ($comments):
		?>
		<div class="w2dc-comments-container">
			<?php foreach ($comments as $comment) : ?>
				<?php $this->display_comment($comment); ?>
				<?php $this->display_comments_node($post_id, $comment->comment_ID); ?>
			<?php endforeach; ?>
		</div>
		<?php
		endif;
	}
	
	public function display_comment($comment) {
		$user = new WP_User($comment->user_id);
		$class = null;
		if (!empty($user->roles) && is_array($user->roles)) {
			foreach ($user->roles as $role) {
				$class = $role;
			}
		} else {
			$class = 'annon';
		}
		?>
		<div class="w2dc-comments-content w2dc-comments-<?php echo $class; ?>" id="comment-<?php echo $comment->comment_ID; ?>">
			<div class="w2dc-comments-p">
				<?php w2dc_comments_profile_pic($comment->comment_author_email); ?>
				<?php print $comment->comment_content; ?><br />
				<time class="meta">
					<strong><?php $user = get_user_by('login', $comment->comment_author); if (!empty($user->user_url)) : ?><a href="<?php print $user->user_url; ?>" target="_blank"><?php print $comment->comment_author; ?></a><?php else : ?><?php print $comment->comment_author; ?><?php endif; ?></strong>
					<?php print human_time_diff(strtotime($comment->comment_date), current_time('timestamp')); ?> ago. <a class="w2dc-comment-reply" data-comment-id="<?php echo $comment->comment_ID; ?>" data-comment-author="<?php echo esc_attr($comment->comment_author); ?>" href="javascript: void(0);"><?php _e('Reply ↓', 'W2DC'); ?></a>
				</time>
			</div>
		</div>
		<?php 
	}
	
	/**
	 * Inserts a comment for the current post if the user is logged in.
	 *
	 * @since 0.1-alpha
	 * @uses check_ajax_referer()
	 * @uses is_user_logged_in()
	 * @uses wp_insert_comment()
	 * @uses wp_get_current_user()
	 * @uses current_time()
	 * @uses wp_kses()
	 * @uses get_option()
	 */
	public function comments_add_comment() {
		check_ajax_referer('w2dc_comments_nonce', 'security');

		$comment = trim(
				wp_kses( $_POST['comment'],
						array(
								'a' => array(
										'href'  => array(),
										'title' => array()
								),
								'br'         => array(),
								'em'         => array(),
								'strong'     => array(),
								'blockquote' => array(),
								'code'       => array()
						)
				)
		);
	
		if (empty($comment)) die();
	
		if (get_option('comment_registration') == 1 && ! is_user_logged_in()) die();
	
		$data = array(
				'comment_post_ID' => (int)$_POST['post_id'],
				'comment_content' => $comment,
				'comment_type' => '',
				'comment_parent' => (int)$_POST['comment_parent'],
				'comment_author_IP' => $_SERVER['REMOTE_ADDR'],
				'comment_agent' => $_SERVER['HTTP_USER_AGENT'],
				'comment_date' => current_time('mysql'),
				'comment_approved' => 1
		);
	
		if (is_user_logged_in()) {
			$current_user = wp_get_current_user();
	
			$author_email = $current_user->user_email;
			$author_url = $current_user->user_url;
			$author_name = $current_user->user_nicename;
	
			$data['user_id'] = $current_user->ID;
		} else {
			$author_email = empty( $_POST['user_email'] ) ? null : esc_attr( $_POST['user_email'] );
			$author_url = empty( $_POST['user_url'] ) ? null : esc_url( $_POST['user_url'], array('http','https') );
			$author_name = empty( $_POST['user_name'] ) ? null : esc_attr( $_POST['user_name'] );
		}
	
		$data['comment_author'] = $author_name;
		$data['comment_author_email'] = $author_email;
		$data['comment_author_url'] = $author_url;
	
		wp_insert_comment($data);
	
		die();
	}
}

function w2dc_comments_profile_pic($id_or_email = null, $email = null) {
	if (is_null($id_or_email)) {
		$current_user = wp_get_current_user();
		$id_or_email = $current_user->ID;
	}

	$html = get_avatar($id_or_email, 32);

	echo '<span class="w2dc-comments-profile-pic-container">' . $html . '</span>';
}

?>
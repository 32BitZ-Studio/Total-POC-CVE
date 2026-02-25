<div class="w2dc-demo-prev-next-demos">
	<span class="w2dc-demo-prev-demo"><?php esc_html_e("Prev demo:", "W2DC"); ?> <a href="<?php echo get_permalink($prev_page); ?>"><?php echo $prev_page->post_title; ?></a></span>
	<span class="w2dc-demo-next-demo"><?php esc_html_e("Next demo:", "W2DC"); ?> <a href="<?php echo get_permalink($next_page); ?>"><?php echo $next_page->post_title; ?></a></span>
</div>
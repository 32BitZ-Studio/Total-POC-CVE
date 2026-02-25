<div class="wcsearch-demo-prev-next-demos">
	<span class="wcsearch-demo-prev-demo"><?php esc_html_e("Prev demo:", "WCSEARCH"); ?> <a href="<?php echo get_permalink($prev_page); ?>"><?php echo $prev_page->post_title; ?></a></span>
	<span class="wcsearch-demo-next-demo"><?php esc_html_e("Next demo:", "WCSEARCH"); ?> <a href="<?php echo get_permalink($next_page); ?>"><?php echo $next_page->post_title; ?></a></span>
</div>
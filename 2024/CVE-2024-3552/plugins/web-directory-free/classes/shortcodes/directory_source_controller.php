<?php

add_shortcode('webdirectory-source', 'w2dc_render_source_shortcode');
function w2dc_render_source_shortcode($args, $shortcode_content) {
	global $post;

	if ($post) {

		if (!$shortcode_content) {
			$post_content = wpautop(strip_tags(get_post($post)->post_content));
		} else {
			$post_content = wpautop($shortcode_content);
		}
		
		$post_content = str_replace(array("[" , "]"), array("[[" , "]]"), $post_content);

		$out = '<div class="w2dc-source-shortcode" style="padding: 20px 0;">' . $post_content . '</div>';

		$out = str_replace('<p>[[webdirectory-source]]</p>', '', $out);
		$out = str_replace('<p>[[webdirectory-demo-links]]</p>', '', $out);
		
		$out = do_shortcode($out);
		
		return $out;
	}
}

?>
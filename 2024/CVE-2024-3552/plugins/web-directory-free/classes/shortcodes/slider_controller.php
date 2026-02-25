<?php 

/**
 *  [webdirectory-slider] shortcode
 *
 *
 */
class w2dc_slider_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		global $w2dc_instance;
		
		parent::init($args);

		$shortcode_atts = array_merge(array(
				'slides' => 5,
				'captions' => 1,
				'pager' => 1,
				'width' => '',
				'height' => 0,
				'slide_width' => 0,
				'max_slides' => 1, // max slides in viewport divided by slide_width
				'sticky_featured' => 0,
				'auto_slides' => 0,
				'auto_slides_delay' => 3000,
				'order_by' => 'post_date',
				'order' => 'ASC',
				'order_by_rand' => 0,
				'crop' => 1,
				'include_categories_children' => 1,
				'author' => 0,
				'related_categories' => 0,
				'related_locations' => 0,
				'related_tags' => 0,
				'related_listing' => 0,
				'include_get_params' => 0,
		), $args);
		$shortcode_atts = apply_filters('w2dc_related_shortcode_args', $shortcode_atts, $args);

		$this->args = $shortcode_atts;

		$args = array(
				'post_type' => W2DC_POST_TYPE,
				'post_status' => 'publish',
				'meta_query' => array(
						array('key' => '_thumbnail_id'),
				),
				'posts_per_page' => $this->args['slides'],
				'paged' => -1,
		);
		if ($this->args['order_by_rand'])
			$args['orderby'] = 'rand';
		else
			$args = array_merge($args, apply_filters('w2dc_order_args', array(), $shortcode_atts, false));
		
		if ($shortcode_atts['author']) {
			$args['author'] = $shortcode_atts['author'];
		}

		if (!empty($this->args['post__in'])) {
			if (is_string($this->args['post__in']) || is_numeric($this->args['post__in'])) {
				$args = array_merge($args, array('post__in' => explode(',', $this->args['post__in'])));
			} elseif (is_array($this->args['post__in'])) {
				$args['post__in'] = $this->args['post__in'];
			}
		}
		if (!empty($this->args['post__not_in'])) {
			$args = array_merge($args, array('post__not_in' => explode(',', $this->args['post__not_in'])));
		}
		
		if (!empty($this->args['directories'])) {
			if ($directories_ids = array_filter(explode(',', $this->args['directories']), 'trim')) {
				$args = w2dc_set_directory_args($args, $directories_ids);
			}
		}
		
		/* if (isset($this->args['levels']) && !is_array($this->args['levels'])) {
			if ($levels = array_filter(explode(',', $this->args['levels']), 'trim')) {
				$this->levels_ids = $levels;
				add_filter('posts_where', array($this, 'where_levels_ids'));
			}
		}

		if (isset($this->args['levels']) || $this->args['sticky_featured']) {
			add_filter('posts_join', 'w2dc_join_levels');
			if ($this->args['sticky_featured'])
				add_filter('posts_where', 'w2dc_where_sticky_featured');
		} */
		$this->query = new WP_Query($args);
		$this->processQuery(false);
		//var_dump($this->query->request);

		if ($this->args['sticky_featured']) {
			remove_filter('posts_join', 'w2dc_join_levels');
			remove_filter('posts_where', 'w2dc_where_sticky_featured');
		}

		if ($this->levels_ids)
			remove_filter('posts_where', array($this, 'where_levels_ids'));
		
		$this->template = 'frontend/slider.tpl.php';

		apply_filters('w2dc_slider_controller_construct', $this);
	}
	
	public function where_levels_ids($where = '') {
		if ($this->levels_ids)
			$where .= " AND (w2dc_levels.id IN (" . implode(',', $this->levels_ids) . "))";
		return $where;
	}

	public function display() {
		$thumbs = array();
		$images = array();
		
		if ($this->args['related_listing']) {
			$listing = w2dc_isListing();
			
			if ($listing->images) {
				foreach ($listing->images AS $attachment_id=>$image) {
					$image_src = wp_get_attachment_image_src($attachment_id, 'full');
					$image_title = $image['post_title'];
					
					$image_tag = '<img src="' . $image_src[0] . '" alt="' . esc_attr($image_title) . '" title="' . esc_attr($image_title) . '" />';
					$thumbs[] = $image_tag;
					$images[] = $image_tag;
				}
			}
		} else {
			while ($this->query->have_posts()) {
				$this->query->the_post();
				$listing = $this->listings[get_the_ID()];
				if ($thumbnail_id = get_post_thumbnail_id(get_the_ID())) {
					$image_src = wp_get_attachment_image_src($thumbnail_id, 'full');
						
					$image_tag = '<img src="' . $image_src[0] . '" alt="' . esc_attr($listing->title()) . '" title="' . esc_attr($listing->title()) . '" />';
					$thumbs[] = $image_tag;
					
					if ($listing->level->listings_own_page) {
						$images[] = '<a href="' . get_the_permalink() . '" ' . (($listing->level->nofollow) ? 'rel="nofollow"' : '') . '>' . $image_tag . '</a>';
					} else {
						$images[] = $image_tag;
					}
				}
			}
		}
		
		if ($images) {
			$output =  w2dc_renderTemplate($this->template, array(
					'captions' => $this->args['captions'],
					'slide_width' => $this->args['slide_width'],
					'max_slides' => $this->args['max_slides'],
					'height' => $this->args['height'],
					'auto_slides' => $this->args['auto_slides'],
					'auto_slides_delay' => $this->args['auto_slides_delay'],
					'crop' => $this->args['crop'],
					'images' => $images,
					'thumbs' => $thumbs,
					'pager' => $this->args['pager'],
					'id' => w2dc_generateRandomVal()
			), true);
			wp_reset_postdata();
				
			return $output;
		}
	}
}

?>
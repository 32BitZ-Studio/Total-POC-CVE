<?php 

/*
 * [wcsearch] shortcode
*
*
*/
class wcsearch_search_form_controller {
	public $args;
	public $search_form;
	
	public function init($args = array()) {
		
		if (!empty($args['id']) || !empty($args['form_id'])) {
			
			$this->args = array_merge(array(
					'id' => '',
					'form_id' => '',
					'params' => '',
			), $args);
			
			$post_id = wcsearch_getValue($this->args, "id", wcsearch_getValue($this->args, "form_id"));
		}
		if (empty($post_id)) {
			if ($form_post = wcsearch_get_on_shop_page()) {
				$post_id = $form_post->ID;
			}
		}
		
		if (!empty($post_id)) {
			$this->search_form = new wcsearch_search_form();
			$this->search_form->getArgByPostId($post_id);
			
			if (!empty($this->args['params'])) {
				$params_str = html_entity_decode($this->args['params']);
				$params_array = wcsearch_get_params_from_string($params_str);
				
				foreach ($params_array AS $name=>$value) {
					$this->search_form->setCommonField($name, $value);
					$this->search_form->setCountField($name, $value);
				}
				
				add_filter("wcsearch_get_count_num_args", array($this, "get_count_num_args"));
			}
		}
		
		apply_filters('wcsearch_search_controller_construct', $this);
	}
	
	public function get_count_num_args($args) {
		
		if (!empty($this->args['params'])) {
			$count_params_str = html_entity_decode($this->args['params']);
			$count_params_array = wcsearch_get_params_from_string($count_params_str);
	
			if ($count_params_array) {
				$args = array_merge($args, array_filter($count_params_array));
	
				$taxonomies = wc_get_taxonomies();
				foreach ($taxonomies AS $tax_name=>$tax_slug) {
					if (empty($args['taxonomies'][$tax_name]) && !empty($count_params_array[$tax_slug])) {
						$args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_args($tax_slug, $count_params_array);
					}
				}
			}
		}
	
		return $args;
	}

	public function display() {
		
		ob_start();
		
		if ($this->search_form) {
			$this->search_form->display();
		}
		
		$output = ob_get_clean();

		return $output;
	}
}

?>
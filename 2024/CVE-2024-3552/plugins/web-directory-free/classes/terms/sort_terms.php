<?php

/**
 * Thanks to Simple Taxonomy Ordering plugin
 * https://wordpress.org/plugins/simple-taxonomy-ordering/
 *
 */

class w2dc_sort_terms {
	public $taxonomies = array(W2DC_CATEGORIES_TAX, W2DC_LOCATIONS_TAX);
	public $init_flag = false;
	
	public function __construct() {
		add_action('admin_head', array($this, 'admin_terms_page'));
		add_action('wp_ajax_w2dc_update_tax_order', array($this, 'update_tax_order'));
		
		if (!isset($_GET['orderby'])) {
			add_filter('terms_clauses', array($this, 'sql_tax_order'), 10, 3);
		}
	}
	
	public function admin_terms_page() {
		$screen = function_exists('get_current_screen') ? get_current_screen() : '';
		
		if ($screen && ! empty($screen->base) && $screen->base === 'edit-tags' && in_array($screen->taxonomy, $this->taxonomies)) {
			wp_enqueue_script('jquery-ui-sortable');
			wp_localize_script(
				'jquery-ui-sortable',
				'w2dc_order_term_data',
				array(
					'term_order_nonce' => wp_create_nonce('term_order_nonce'),
					'paged'            => isset($_GET['paged']) ? absint(wp_unslash($_GET['paged'])) : 0,
					'per_page_id'      => "edit_{$screen->taxonomy}_per_page",
				)
			);
			
			$this->default_term_order($screen->taxonomy);
		}
	}
	
	public function default_term_order($tax_slug) {
		$this->init_flag = true;
		$terms = get_terms($tax_slug, array('hide_empty' => false));
		$this->init_flag = false;
		$order = $this->get_max_taxonomy_order($tax_slug);
		foreach ($terms as $term) {
			if (!get_term_meta($term->term_id, 'tax_position', true)) {
				update_term_meta($term->term_id, 'tax_position', $order);
				$order++;
			}
		}
	}
	
	public function get_max_taxonomy_order($tax_slug) {
		global $wpdb;
		$max_term_order = $wpdb->get_var(
				$wpdb->prepare(
						"SELECT MAX( CAST( tm.meta_value AS UNSIGNED ) )
						FROM $wpdb->terms t
						JOIN $wpdb->term_taxonomy tt ON t.term_id = tt.term_id AND tt.taxonomy = '%s'
						JOIN $wpdb->termmeta tm ON tm.term_id = t.term_id WHERE tm.meta_key = 'tax_position'",
						$tax_slug
				)
		);
		return (int)$max_term_order;
	}
	
	public function sql_tax_order($pieces, $taxonomies, $args) {
		if (!$this->init_flag) {
			foreach ($taxonomies as $taxonomy) {
				if (in_array($taxonomy, $this->taxonomies)) {
					global $wpdb;
		
					$join_statement = " LEFT JOIN $wpdb->termmeta AS term_meta ON t.term_id = term_meta.term_id AND term_meta.meta_key = 'tax_position'";
		
					if (strpos($pieces['join'], $join_statement) === false) {
						$pieces['join'] .= $join_statement;
					}
					$pieces['orderby'] = 'ORDER BY CAST(term_meta.meta_value AS UNSIGNED)';
				}
			}
		}
		
		return $pieces;
	}
	
	public function update_tax_order() {
		if (!check_ajax_referer('term_order_nonce', 'term_order_nonce', false)) {
			wp_send_json_error();
		}
	
		$taxonomy_ordering_data = filter_var_array( wp_unslash( $_POST['taxonomy_ordering_data'] ), FILTER_SANITIZE_NUMBER_INT);
		$base_index             = filter_var( wp_unslash( $_POST['base_index'] ), FILTER_SANITIZE_NUMBER_INT) ;
		foreach ($taxonomy_ordering_data as $order_data) {
	
			// Due to the way WordPress shows parent categories on multiple pages, we need to check if the parent category's position should be updated.
			// If the category's current position is less than the base index (i.e. the category shouldn't be on this page), then don't update it.
			if ($base_index > 0) {
				$current_position = get_term_meta( $order_data['term_id'], 'tax_position', true );
				if ((int)$current_position < (int)$base_index) {
					continue;
				}
			}
	
			update_term_meta($order_data['term_id'], 'tax_position', ((int)$order_data['order'] + (int) $base_index));
		}
	
		wp_send_json_success();
	}
}

?>
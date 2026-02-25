<?php

class w2dc_orderingLinks {
	public $links = array();
	public $active_link;
	public $active_link_name;
	public $active_link_order;
	public $ordering;
	public $base_url;
	public $order_by;
	public $order;

	public function __construct($ordering, $base_url, $order_by, $order) {
		$this->ordering = $ordering;
		$this->base_url = $base_url;
		$this->order_by = $order_by;
		$this->order = $order;
	}

	public function addLinks($ordering) {
		$this->ordering = array_merge($this->ordering, $ordering);
	}

	public function getLinks($order_by_param_name, $order_param_name) {
		foreach ($this->ordering AS $field_slug=>$field) {
			if (is_array($field)) {
				foreach ($field AS $order=>$field_name) {
					if ($this->order_by == $field_slug && $this->order == $order) {
						$this->active_link = $field_slug;
						$this->active_link_name = $field_name;
						$this->active_link_order = $order;
					}
					$url = esc_url(add_query_arg(array($order_by_param_name => $field_slug, $order_param_name => $order), $this->base_url));
						
					$this->links[] = array('field_slug' => $field_slug, 'url' => $url, 'field_name' => $field_name, 'order' => $order);
				}
			} else {
				$field_name = $field;
				$order = 'ASC';
				
				if ($this->order_by == $field_slug) {
					$this->active_link = $field_slug;
					$this->active_link_name = $field_name;
					$this->active_link_order = $order;
				}
				$url = esc_url(add_query_arg(array($order_by_param_name => $field_slug, $order_param_name => $order), $this->base_url));
				
				$this->links[] = array('field_slug' => $field_slug, 'url' => $url, 'field_name' => $field_name, 'order' => $order);
			}
		}
		
		return $this->links;
	}
}

?>
<?php 

class w2dc_search_query extends wcsearch_query {
	
	public function __construct($args, $no_order = false) {
	
		$this->args = apply_filters("w2dc_query_args_validate", $args);
	
		$this->q_args = array(
				'post_type' => W2DC_POST_TYPE,
				'post_status' => 'publish',
				'paged' => w2dc_getValue($this->args, 'paged', 1),
		);
	
		$this->q_args = apply_filters("w2dc_query_args", $this->q_args, $this->args);
		
		if (!$no_order) {
			$this->q_args = apply_filters("w2dc_order_args", $this->q_args, $this->args);
		}
		
		//var_dump($this->q_args);
	
		$this->query = new WP_Query($this->q_args);
		//var_dump($this->query->request);
	}
}
?>
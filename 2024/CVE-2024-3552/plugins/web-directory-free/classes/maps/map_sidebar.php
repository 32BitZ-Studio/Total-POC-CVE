<?php

class w2dc_map_sidebar {
	public $listings_content = '';
	public $uid;
	public $map_args;
	public $search_form;

public function __construct($map_id, $map_args, $listings_content = '') {

		$this->uid = $map_id;
		$this->map_args = $map_args;
		$this->listings_content = $listings_content;

		if ($this->isSearchForm()) {
			
			$this->search_form = new wcsearch_search_form;
			$this->search_form->setArgs(array('hash' => $this->uid));
			$this->search_form->setCommonField("used_by", "w2dc");
			
			if (!isset($this->map_args['search_on_map_id'])) {
				$this->search_form->setArgsFromOldForm($this->map_args);
			} elseif (!empty($this->map_args['search_on_map_id'])) {
				$this->search_form->getArgByPostId($this->map_args['search_on_map_id']);
			}
			
			$this->search_form->setCountFields($this->map_args);
				
			wcsearch_setFrontendController("wcsearch");
		}
	}

	public function isSearchForm() {
		
		if (!empty($this->map_args['search_on_map']) && (!isset($this->map_args['search_on_map_id']) || !empty($this->map_args['search_on_map_id']))) {
			return true;
		}
	}
	
	public function isStickyScroll() {
		
		if (!empty($this->map_args['search_on_map_id']) && !empty($this->search_form->args['sticky_scroll'])) {
			return true;
		}
	}
	
	public function isListings() {
		
		if (!empty($this->map_args['search_on_map_listings']) && $this->map_args['search_on_map_listings'] == 'sidebar') {
			return true;
		}
	}
	
	public function isSidebar() {
		
		if (!$this->isStickyScroll() || ($this->isListings())) {
			return true;
		}
	}
	
	public function display($height = 600) {
		
		if (!empty($this->map_args['search_on_map'])) {
		
			w2dc_renderTemplate('maps/map_sidebar.tpl.php',
					array(
							'uid' => $this->uid,
							'search_map' => $this,
							'search_form' => $this->search_form,
							'map_args' => $this->map_args,
							'height' => $height,
					)
			);
		}
	}
}
?>
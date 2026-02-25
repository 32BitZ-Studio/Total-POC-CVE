<?php

class w2dc_search_form {
	public $search_form;
	
	public function __construct($hash = null, $args = array()) {
		
		$this->search_form = new wcsearch_search_form;
		$this->search_form->setArgs(array('hash' => $hash));
		$this->search_form->setCommonField("used_by", "w2dc");
			
		if (!empty($args['form_id'])) {
			$this->search_form->getArgByPostId($args['form_id']);
		} else {
			$this->search_form->setArgsFromOldForm($args);
		}
		
		$this->search_form->setCountFields($args);
		
		wcsearch_setFrontendController("wcsearch");
	}
	
	public function display() {
		
		if ($this->search_form) {
			$this->search_form->display();
		}
	}
}

?>
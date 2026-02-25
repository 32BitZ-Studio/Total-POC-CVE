<?php

class w2dc_breadcrumb {
	public $url;
	public $name;
	public $title;
	
	/**
	 * escape HTML on name and title
	 * 
	 * @param string $name
	 * @param string $url
	 * @param string $title
	 */
	public function __construct($name, $url = '', $title = '') {
		$this->url = $url;
		$this->name = $name;
		$this->title = $title;
	}
}

?>
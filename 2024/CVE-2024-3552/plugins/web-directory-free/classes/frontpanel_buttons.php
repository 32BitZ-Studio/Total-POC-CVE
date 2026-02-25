<?php

class w2dc_frontpanel_buttons {
	public $args = array();
	public $hide_button_text = false;
	public $directories = array();
	public $buttons = false;
	public $listing = false;
	
	public function __construct($args = array()) {
		global $w2dc_instance;
		
		$this->args = array_merge(array(
				'directories' => '',
				'hide_button_text' => false,
				'buttons' => 'submit,claim,favourites,edit,print,bookmark,pdf', // also 'logout' possible
		), $args);
		
		if (!empty($this->args['directories'])) {
			if (!is_array($this->args['directories'])) {
				$directories_ids = array_filter(explode(',', $this->args['directories']), 'trim');
			} else {
				$directories_ids = $this->args['directories'];
			}
		}
		
		if ($this->args['buttons']) {
			if (is_array($this->args['buttons'])) {
				$this->buttons = $this->args['buttons'];
			} else {
				$this->buttons = array_filter(explode(',', $this->args['buttons']), 'trim');
			}
		}
		
		if (!$this->args['directories']) {
			if ($w2dc_instance->current_directory) {
				$this->directories[] = $w2dc_instance->current_directory;
			} else {
				$this->directories[] = $w2dc_instance->directories->getDefaultdirectory();
			}
		} elseif ($this->args['directories'] == 'all') {
			foreach ($w2dc_instance->directories->directories_array AS $directory) {
				$this->directories[] = $directory;
			}
		} elseif (isset($directories_ids)) {
			foreach ($directories_ids AS $id) {
				$this->directories[] = $w2dc_instance->directories->getDirectoryById($id);
			}
		}
		
		$this->listing = w2dc_isListing();

		$this->hide_button_text = apply_filters('w2dc_frontpanel_buttons_hide_text', $this->args['hide_button_text'], $this);
	}
	
	public function getDirectories() {
		return $this->directories;
	}

	public function isButton($button) {
		return (in_array($button, $this->buttons));
	}

	public function isFavouritesButton() {
		global $w2dc_instance;

		return ($this->isButton('favourites') && get_option('w2dc_favourites_list') && $w2dc_instance->action != 'myfavourites');
	}

	public function isEditButton() {
		return ($this->isListing() && $this->isButton('edit') && w2dc_show_edit_button($this->getListingId()));
	}

	public function isPrintButton() {
		return ($this->isListing() && $this->isButton('print') && get_option('w2dc_print_button'));
	}

	public function isPdfButton() {
		return ($this->isListing() && $this->isButton('pdf') && get_option('w2dc_pdf_button'));
	}

	public function isBookmarkButton() {
		return ($this->isListing() && $this->isButton('bookmark') && get_option('w2dc_favourites_list'));
	}

	public function isListing() {
		return (bool)($this->listing);
	}

	public function getListingId() {
		if ($this->listing) {
			return $this->listing->post->ID;
		}
	}
	
	public function tooltipMeta($text, $return = false) {
		if ($this->hide_button_text) {
			$out = 'data-toggle="w2dc-tooltip" data-placement="top" data-original-title="' . esc_attr($text) . '"';;
			if ($return) {
				return $out;
			} else {
				echo $out;
			}
		}
	}
	
	public function display($return = false) {
		return w2dc_renderTemplate('frontend/frontpanel_buttons.tpl.php', array('frontpanel_buttons' => $this), $return);
	}
}
?>
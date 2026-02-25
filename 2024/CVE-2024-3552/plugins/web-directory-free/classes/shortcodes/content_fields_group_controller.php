<?php 

/**
 *  [webdirectory-content-fields-group] shortcode
 *
 *
 */
class w2dc_content_fields_group_controller extends w2dc_content_field_controller {
	
	public function display() {
		if ($this->listing && $this->args['id']) {
			ob_start();
			
			echo '<div class="w2dc-content">';
			$this->listing->renderContentFieldsGroup($this->args['id'], $this->args['classes']);
			echo '</div>';
			
			return ob_get_clean();
		}
	}
}

?>
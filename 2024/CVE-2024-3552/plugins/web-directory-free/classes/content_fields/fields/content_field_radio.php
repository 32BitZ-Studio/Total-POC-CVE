<?php 

class w2dc_content_field_radio extends w2dc_content_field_select {
	protected $can_be_searched = true;

	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/radio_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/radio_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this));
	}
}
?>
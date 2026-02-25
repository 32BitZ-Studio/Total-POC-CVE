<?php

abstract class wcsearch_widget extends WP_Widget {
	protected $fields = array();

	public function __construct($id_base, $name, $description = '') {
		$options["description"] = $description;
		
		parent::__construct($id_base, $name, $options);
		
		$this->addField("textfield", "title", esc_html__("Title", "WCSEARCH"));

		// enqueue scripts and styles only for directory widgets and when "Show only on directory pages" setting is OFF or this setting does not exist for this widget
		add_action('wp_enqueue_scripts', array($this, 'wp_enqueue_scripts'));
		add_action('wp_enqueue_scripts', array($this, 'wp_enqueue_custom_style'), 9999);
	}
	
	public function wp_enqueue_scripts() {
		global $wcsearch_instance;
		
		$widget_options_all = get_option($this->option_name);
		if (isset($widget_options_all[$this->number])) {
			$current_widget_options = $widget_options_all[$this->number];
			if (is_active_widget(false, false, $this->id_base, true) && (empty($current_widget_options['visibility']) || !empty($wcsearch_instance->frontend_controllers))) {
				$wcsearch_instance->enqueue_scripts_styles(true);
			}
		}
	}
	
	public function wp_enqueue_custom_style() {
		global $wcsearch_instance;
		
		$widget_options_all = get_option($this->option_name);
		if (isset($widget_options_all[$this->number])) {
			$current_widget_options = $widget_options_all[$this->number];
			if (is_active_widget(false, false, $this->id_base, true) && (empty($current_widget_options['visibility']) || !empty($wcsearch_instance->frontend_controllers))) {
				$wcsearch_instance->enqueue_scripts_styles_custom(true);
			}
		}
	}
	
	public function addField($type, $name = false, $label = false, $description = false, $options = array(), $std = false, $dependency = array()) {
		$field = new stdClass();
		
		$field->name = $name;
		$field->type = $type;
		$field->label = $label;
		$field->description = $description;
		$field->options = $options;
		$field->std = $std;
		$field->dependency = $dependency;

		$this->fields[] = $field;
	}

	public function convertParams($params) {
		foreach ($params AS $param) {
			$type = false;
			$name = false;
			$label = false;
			$description = false;
			$options = array();
			$std = false;
			$dependency = false;
			if (isset($param['type'])) {
				$type = $param['type'];
			}
			if (isset($param['param_name'])) {
				$name = $param['param_name'];
			}
			if (isset($param['heading'])) {
				$label = $param['heading'];
			}
			if (isset($param['description'])) {
				$description = $param['description'];
			}
			if (isset($param['value'])) {
				if (is_array($param['value'])) {
					$options = $param['value'];
				} else {
					$std = $param['value'];
				}
			}
			if (isset($param['std'])) {
				$std = $param['std'];
			}
			if (isset($param['dependency'])) {
				$dependency = $param['dependency'];
			}
			$this->addField($type, $name, $label, $description, $options, $std, $dependency);
		}
	}
	
	public function update($new_instance, $old_instance) {
		foreach($this->fields as $field){
			$field = (object) $field;
			
			if (isset($new_instance[$field->name])) {
				$old_instance[$field->name] = $new_instance[$field->name];
			} else {
				$old_instance[$field->name] = '';
			}
		}
		
		return $old_instance;
	}
	
	public function renderLabel($field, $id){
		if (!empty($field->label)) {
			echo "<label for=\"{$id}\">" . esc_html($field->label) . "</label>";
		}
	}

	public function renderDescription($field){
		if (!empty($field->description)) {
			echo "<span class=\"wcsearch-widget-description\">" . esc_html($field->description) . "</span>";
		}
	}

	public function renderDependency($field){
		if ($field->dependency) {
			echo "<span class=\"wcsearch-widget-dependency\" data-dependency-element=\"{$field->dependency['element']}\" data-dependency-value=\"{$field->dependency['value']}\"></span>";
		}
	}

	public function checkDependency($original_field, $instance){
		if ($original_field->dependency) {
			foreach ($this->fields AS $field) {
				$value = isset($instance[$field->name]) ? $instance[$field->name] : $field->std;
				if (is_array($value)) {
					if ($field->name == $original_field->dependency['element'] && !in_array($original_field->dependency['value'], $value)) {
						return "style=\"display:none\"";
					}
				} else {
					if ($field->name == $original_field->dependency['element'] && $value != $original_field->dependency['value']) {
						return "style=\"display:none\"";
					}
				}
			}
		}
	}
	
	public function form($instance) {
		echo '<script>
				(function($) {
					"use strict";
			
					$(function() {
							var inputs = $(".widget-content, .so-content").find("input, select").not(":input[type=text], :input[type=submit], :input[type=reset]");
							inputs.each(function() {
								$(this).on("change", function() {
									var input = $(this);
									var dependencies = input.parents(".widget-content, .so-content").find(".wcsearch-widget-dependency");
									dependencies.each(function() {
										var name = $(this).data("dependency-element");
										var value = $(this).data("dependency-value");
										if (input.data("original-name") == name) {
											if (input.val() == value) {
												$(this).parent("p").show();
											} else {
												$(this).parent("p").hide();
											}
										}
									});
								});
							});
					});
				})(jQuery);
				</script>';
		
		foreach($this->fields as $key => $field){
			$field = (object) $field;
			
			$method_name = "render_{$field->type}_field";
			
			$this->$method_name($field, $instance);
		}
	}
	
	public function widget($args, $instance) {
		$this->render_widget($instance, $args);
	}
	
	abstract public function render_widget($instance, $args);
	
	public function render_textfield_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr($instance[$field->name]) : $field->std;
		
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		echo "<input class=\"widefat\" id=\"{$id}\" name=\"{$name}\" type=\"text\" value=\"{$value}\" />";
		$this->renderDescription($field);
		echo "</p>";
	}
	
	public function render_hidden_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr($instance[$field->name]) : $field->std;
		
		echo "<input id=\"{$id}\" name=\"{$name}\" type=\"hidden\" value=\"{$value}\" />";
	}

	public function render_dropdown_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr($instance[$field->name]) : null;
		$std = $field->std;
		
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		echo "<select class=\"widefat\" id=\"{$id}\" name=\"{$name}\" class=\"widefat wcsearch-widget-select-control\" data-original-name=\"{$field->name}\">";
		foreach ($field->options as $label=>$option_val){
			if (is_int($label)) {
				$label = $option_val;
			}

			if ((!is_null($value) && $option_val == $value) || (is_null($value) && $option_val === $std)) {
				$selected = " selected=\"selected\"";
			} else {
				$selected = "";
			}
			
			echo "<option value=\"{$option_val}\"{$selected}>{$label}</option>";
		}
		echo "</select>";
		$this->renderDescription($field, $id);
		echo "</p>";
	}
	
	public function render_textarea_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr($instance[$field->name]) : $field->std;
		
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		echo "<textarea id=\"{$id}\" name=\"{$name}\" style=\"display:block;width:100%;\">{$value}</textarea>";
		$this->renderDescription($field, $id);
		echo "</p>";
	}

	public function render_formid_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? $instance[$field->name] : 0;
			
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		echo "<select id=\"{$name}" . "\" name=\"{$name}" . "\" " . "class=\"widefat wcsearch-widget-select-control\"" . ">";
		echo "<option value=\"0\" " . selected($value, 0) . ">" . esc_html__('- Select Form -', 'WCSEARCH') . "</option>";
		foreach (wcsearch_get_search_forms_posts() AS $id=>$title) {
			echo "<option value=\"{$id}\" " . (($value == $id) ? "selected=\"selected\"" : "") . ">{$title}</option>";
		}
		echo "</select>";
		$this->renderDescription($field, $id);
		echo "</p>";
	}
	
	public function outputJSforMultipleDropBox() {
		$out = '<script>
				(function($) {
					"use strict";
				
					$("body").on("change", ".wcsearch-widget-select-multiple-control", function() {
						$(this).next("input").val($(this).val());
					})
				})(jQuery);
				</script>';
		echo $out;
	}

	public function render_checkbox_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		if (!$field->options) {
			$value = isset($instance[$field->name]) ? $instance[$field->name] : $field->std;
		} else {
			$value = isset($instance[$field->name]) ? $instance[$field->name] : $field->std;
		}

		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		if (!$field->options) {
			$checked = "";
			if ($value == 1) {
				$checked = "checked = \"checked\"";
			}
			echo "<input id=\"{$id}\" name=\"{$name}\" type=\"checkbox\" value=\"1\" {$checked} data-original-name=\"{$field->name}\" />";
			$this->renderLabel($field, $id);
		} else {
			$this->renderLabel($field, $id);
			foreach ($field->options AS $option_name=>$key) {
				$checked = "";
				if (is_array($value) && in_array($key, $value)) {
					$checked = "checked = \"checked\"";
				}
				echo "<br />";
				echo "<label>";
				echo "<input name=\"{$name}[]\" type=\"checkbox\" value=\"{$key}\" {$checked}/>";
				echo esc_html($option_name);
				echo "</label>";
			}
		}
		$this->renderDescription($field, $id);
		echo "</p>";
	}

	public function render_colorpicker_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr(strip_tags($instance[$field->name])) : $field->std;

		echo '<script>
				(function($) {
					"use strict";
					$(function() {
						$(".wcsearch-select-color").wpColorPicker({
							change: function(event, ui) {
								$(this).parents("form").find("input[type=submit]").trigger("change");
								$(this)
								.val(ui.color.toString())
								.trigger("change");
							}
						});
					});
				})(jQuery);
			</script>';
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		echo "<input
				type=\"text\"
				id=\"{$id}\"
				name=\"{$name}\"
				value=\"{$value}\"
				class=\"wcsearch-select-color widefat\"
			/>";
		$this->renderDescription($field, $id);
		echo "</p>";
	}
	
	public function render_datefieldmin_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr(strip_tags($instance[$field->name])) : $field->std;
		if (!is_numeric($value)) {
			$value = strtotime($value);
		}

		$settings['field_id'] = $id;
		$settings['param_name'] = $name;
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		wcsearch_renderTemplate('search_fields/fields/datetime_input_vc_min.tpl.php', array('settings' => $settings, 'value' => $value, 'dateformat' => wcsearch_getDatePickerFormat()));
		$this->renderDescription($field, $id);
		echo "</p>";
	}

	public function render_datefieldmax_field($field, $instance) {
		$id = $this->get_field_id($field->name);
		$name = $this->get_field_name($field->name);
		$value = isset($instance[$field->name]) ? esc_attr(strip_tags($instance[$field->name])) : $field->std;
		if (!is_numeric($value)) {
			$value = strtotime($value);
		}

		$settings['field_id'] = $id;
		$settings['param_name'] = $name;
		echo "<p " . $this->checkDependency($field, $instance) . ">";
		$this->renderDependency($field);
		$this->renderLabel($field, $id);
		wcsearch_renderTemplate('search_fields/fields/datetime_input_vc_max.tpl.php', array('settings' => $settings, 'value' => $value, 'dateformat' => wcsearch_getDatePickerFormat()));
		$this->renderDescription($field, $id);
		echo "</p>";
	}

	public function render_hr_field($field, $instance) {
		echo "<hr/>";
	}
}

add_action('admin_enqueue_scripts', 'wcsearch_widgets_enqueue_scripts');
function wcsearch_widgets_enqueue_scripts($hook) {
	if ($hook == "widgets.php"){
		wp_enqueue_style( 'wp-color-picker' );
		wp_enqueue_script( 'wp-color-picker' );
	}
}

add_action('widgets_init', 'wcsearch_register_widgets');
function wcsearch_register_widgets() {
	foreach (get_declared_classes() as $class) {
		if (is_subclass_of($class, "wcsearch_widget")) {
			register_widget($class);
		}
	}
}

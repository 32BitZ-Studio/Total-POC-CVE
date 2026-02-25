<?php 

global $wcsearch_model_options;
$wcsearch_model_options = array(
		'keywords' => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => esc_html__("Keywords", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "placeholder",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => esc_html__("Enter keywords", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "string",
						"name" => "try_to_search_text",
						"title" => esc_html__("Try to search text", "WCSEARCH"),
						"value" => esc_html__("Try to search", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "keywords_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "sport,business,event",
				),
				array(
						"type" => "select",
						"name" => "autocomplete",
						"title" => esc_html__("Autocomplete field", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
				),
				/* array(
						"type" => "select",
						"name" => "orderby",
						"title" => esc_html__("Order items", "WCSEARCH"),
						"options" => array(
								"relevance" => esc_html__("By relevance", "WCSEARCH"),
								"price" => esc_html__("By price", "WCSEARCH"),
						),
						"value" => "relevance",
						"dependency" => array('autocomplete' => 1),
				), */
				array(
						"type" => "select",
						"name" => "order",
						"title" => esc_html__("Order direction", "WCSEARCH"),
						"options" => array(
								"ASC" => esc_html__("ASC", "WCSEARCH"),
								"DESC" => esc_html__("DESC", "WCSEARCH"),
						),
						"value" => "ASC",
						"dependency" => array(
								'autocomplete' => 1,
								'orderby' => 'price'
						),
				),
				array(
						"type" => "select",
						"name" => "do_links",
						"title" => esc_html__("Links to products in autocomplete suggestion", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array('autocomplete' => 1),
				),
				array(
						"type" => "select",
						"name" => "do_links_blank",
						"title" => esc_html__("How to open links", "WCSEARCH"),
						"options" => array(
								"blank" => esc_html__("Open in new window", "WCSEARCH"),
								"self" => esc_html__("Open in same window", "WCSEARCH"),
						),
						"value" => "blank",
						"dependency" => array('autocomplete' => 1, 'do_links' => '1'),
				),
		),
		'string' => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => "",
				),
				array(
						"type" => "string",
						"name" => "placeholder",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => esc_html__("Enter keywords", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "string",
						"name" => "try_to_search_text",
						"title" => esc_html__("Try to search text", "WCSEARCH"),
						"value" => esc_html__("Try to search", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "keywords_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "sport,business,event",
				),
		),
		'address' => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => "",
				),
				array(
						"type" => "string",
						"name" => "placeholder",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => esc_html__("Enter address", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "string",
						"name" => "try_to_search_text",
						"title" => esc_html__("Try to search text", "WCSEARCH"),
						"value" => esc_html__("Try to search", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "address_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "Los Angeles, US Capitol, Central Park NY",
				),
		),
		"price" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => "Price",
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "select",
						"name" => "mode",
						"title" => esc_html__("Search mode", "WCSEARCH"),
						"options" => array(
								"range" => esc_html__("Range slider", "WCSEARCH"),
								"single_slider" => esc_html__("Single slider", "WCSEARCH"),
								"min_max_one_dropdown" => esc_html__("Min-max options in one dropdown", "WCSEARCH"),
								"min_max_two_dropdowns" => esc_html__("Min-max options in two dropdowns", "WCSEARCH"),
								"radios" => esc_html__("Min-max options in radios", "WCSEARCH"),
								"inputs" => esc_html__("Two inputs", "WCSEARCH"),
						),
						"value" => "range",
				),
				array(
						"type" => "string",
						"name" => "placeholder_single_dropdown",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => esc_html__("Select price range", "WCSEARCH"),
						"dependency" => array('mode' => 'min_max_one_dropdown'),
				),
				array(
						"type" => "string",
						"name" => "placeholder_min",
						"title" => esc_html__("Placeholder min", "WCSEARCH"),
						"value" => esc_html__("Select min price", "WCSEARCH"),
						"dependency" => array('mode' => 'min_max_two_dropdowns,inputs'),
				),
				array(
						"type" => "string",
						"name" => "placeholder_max",
						"title" => esc_html__("Placeholder max", "WCSEARCH"),
						"value" => esc_html__("Select max price", "WCSEARCH"),
						"dependency" => array('mode' => 'min_max_two_dropdowns,inputs'),
				),
				array(
						"type" => "select",
						"name" => "show_scale",
						"title" => esc_html__("Show scale", "WCSEARCH"),
						"options" => array(
								"scale" => esc_html__("Show scale", "WCSEARCH"),
								"string" => esc_html__("Show as string", "WCSEARCH"),
						),
						"value" => "string",
						"dependency" => array('mode' => 'range,single_slider'),
				),
				array(
						"type" => "select",
						"name" => "odd_even_labels",
						"title" => esc_html__("Scale labels", "WCSEARCH"),
						"options" => array(
								"odd_even" => esc_html__("Odd and even labels", "WCSEARCH"),
								"odd" => esc_html__("Only odd labels", "WCSEARCH"),
						),
						"value" => "odd",
						"dependency" => array('show_scale' => 'scale'),
				),
				array(
						"type" => "select",
						"name" => "columns",
						"title" => esc_html__("Radios columns", "WCSEARCH"),
						"description" => esc_html__("When radio buttons is used in search mode", "WCSEARCH"),
						"options" => array(
								1 => 1,
								2 => 2,
								3 => 3,
								4 => 4,
								5 => 5,
						),
						"value" => 2,
						"dependency" => array('mode' => 'radios'),
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array('mode' => 'radios'),
				),
				array(
						"type" => "string",
						"name" => "min_max_options",
						"title" => esc_html__("Min-Max options", "WCSEARCH"),
						"description" => "Example: 1,5,10,15,20 or 1-20",
						"value" => "",
						//"value" => "min, 1, 10, 50, 100, 500, 1000, max",
						"dependency" => array('mode' => 'range,single_slider,min_max_one_dropdown,min_max_two_dropdowns,radios'),
				),
				array(
						"type" => "dependency",
						"name" => "dependency_tax",
						"title" => esc_html__("Dependency", "WCSEARCH"),
						"description" => esc_html__("The field will be dependent from selected tax", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("No dependency", "WCSEARCH"),
						),
				),
				array(
						"type" => "select",
						"name" => "dependency_visibility",
						"title" => esc_html__("Dependency visibility", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("Hidden", "WCSEARCH"),
								"1" => esc_html__("Shaded", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array("dependency_tax" => ""),
				),
		),
		"number" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => "Number",
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "select",
						"name" => "mode",
						"title" => esc_html__("Search mode", "WCSEARCH"),
						"options" => array(
								"range" => esc_html__("Range slider", "WCSEARCH"),
								"single_slider" => esc_html__("Single slider", "WCSEARCH"),
								"min_max_one_dropdown" => esc_html__("Min-max options in one dropdown", "WCSEARCH"),
								"min_max_two_dropdowns" => esc_html__("Min-max options in two dropdowns", "WCSEARCH"),
								"radios" => esc_html__("Min-max options in radios", "WCSEARCH"),
								"inputs" => esc_html__("Two inputs", "WCSEARCH"),
						),
						"value" => "range",
				),
				array(
						"type" => "string",
						"name" => "placeholder_single_dropdown",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => esc_html__("Select range", "WCSEARCH"),
						"dependency" => array('mode' => 'min_max_one_dropdown'),
				),
				array(
						"type" => "string",
						"name" => "placeholder_min",
						"title" => esc_html__("Placeholder min", "WCSEARCH"),
						"value" => esc_html__("Select min", "WCSEARCH"),
						"dependency" => array('mode' => 'min_max_two_dropdowns,inputs'),
				),
				array(
						"type" => "string",
						"name" => "placeholder_max",
						"title" => esc_html__("Placeholder max", "WCSEARCH"),
						"value" => esc_html__("Select max", "WCSEARCH"),
						"dependency" => array('mode' => 'min_max_two_dropdowns,inputs'),
				),
				array(
						"type" => "select",
						"name" => "show_scale",
						"title" => esc_html__("Show scale", "WCSEARCH"),
						"options" => array(
								"scale" => esc_html__("Show scale", "WCSEARCH"),
								"string" => esc_html__("Show as string", "WCSEARCH"),
						),
						"value" => "string",
						"dependency" => array('mode' => 'range'),
				),
				array(
						"type" => "select",
						"name" => "odd_even_labels",
						"title" => esc_html__("Scale labels", "WCSEARCH"),
						"options" => array(
								"odd_even" => esc_html__("Odd and even labels", "WCSEARCH"),
								"odd" => esc_html__("Only odd labels", "WCSEARCH"),
						),
						"value" => "odd",
						"dependency" => array('mode' => 'range', 'show_scale' => 'scale'),
				),
				array(
						"type" => "select",
						"name" => "columns",
						"title" => esc_html__("Radios columns", "WCSEARCH"),
						"description" => esc_html__("When radio buttons is used in search mode", "WCSEARCH"),
						"options" => array(
								1 => 1,
								2 => 2,
								3 => 3,
								4 => 4,
								5 => 5,
						),
						"value" => 2,
						"dependency" => array('mode' => 'radios'),
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array('mode' => 'radios'),
				),
				array(
						"type" => "string",
						"name" => "min_max_options",
						"title" => esc_html__("Min-Max options", "WCSEARCH"),
						"description" => "Example: 1,5,10,15,20 or 1-20",
						"value" => "",
						//"value" => "min, 1, 10, 50, 100, 500, 1000, max",
				),
				array(
						"type" => "dependency",
						"name" => "dependency_tax",
						"title" => esc_html__("Dependency", "WCSEARCH"),
						"description" => esc_html__("The field will be dependent from selected tax", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("No dependency", "WCSEARCH"),
						),
				),
				array(
						"type" => "select",
						"name" => "dependency_visibility",
						"title" => esc_html__("Dependency visibility", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("Hidden", "WCSEARCH"),
								"1" => esc_html__("Shaded", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array("dependency_tax" => ""),
				),
		),
		"date" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => "Date",
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "string",
						"name" => "placeholder_start",
						"title" => esc_html__("Placeholder start", "WCSEARCH"),
						"value" => esc_html__("Select start date", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "placeholder_end",
						"title" => esc_html__("Placeholder end", "WCSEARCH"),
						"value" => esc_html__("Select end date", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "reset_label_text",
						"title" => esc_html__("Reset text", "WCSEARCH"),
						"value" => esc_html__("reset", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "view",
						"title" => esc_html__("Show fields", "WCSEARCH"),
						"options" => array(
								"vertically" => esc_html__("Vertically", "WCSEARCH"),
								"horizontally" => esc_html__("Horizontally", "WCSEARCH"),
						),
						"value" => "vertically",
				),
				array(
						"type" => "dependency",
						"name" => "dependency_tax",
						"title" => esc_html__("Dependency", "WCSEARCH"),
						"description" => esc_html__("The field will be dependent from selected tax", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("No dependency", "WCSEARCH"),
						),
				),
				array(
						"type" => "select",
						"name" => "dependency_visibility",
						"title" => esc_html__("Dependency visibility", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("Hidden", "WCSEARCH"),
								"1" => esc_html__("Shaded", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array("dependency_tax" => ""),
				),
		),
		"radius" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => "Radius",
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "select",
						"name" => "mode",
						"title" => esc_html__("Search mode", "WCSEARCH"),
						"options" => array(
								"slider" => esc_html__("Slider", "WCSEARCH"),
								"selectbox" => esc_html__("Selectbox", "WCSEARCH"),
						),
						"value" => "slider",
				),
				array(
						"type" => "select",
						"name" => "show_scale",
						"title" => esc_html__("Show scale", "WCSEARCH"),
						"options" => array(
								"scale" => esc_html__("Show scale", "WCSEARCH"),
								"string" => esc_html__("Show as string", "WCSEARCH"),
						),
						"value" => "string",
						"dependency" => array('mode' => 'slider'),
				),
				array(
						"type" => "select",
						"name" => "odd_even_labels",
						"title" => esc_html__("Scale labels", "WCSEARCH"),
						"options" => array(
								"odd_even" => esc_html__("Odd and even labels", "WCSEARCH"),
								"odd" => esc_html__("Only odd labels", "WCSEARCH"),
						),
						"value" => "odd",
						"dependency" => array('show_scale' => 'scale', 'mode' => 'slider'),
				),
				array(
						"type" => "string",
						"name" => "string_label",
						"title" => esc_html__("Label", "WCSEARCH"),
						"description" => "Example: Search in radius",
						"value" => "Search in radius",
						"dependency" => array('mode' => 'slider'),
				),
				array(
						"type" => "string",
						"name" => "min_max_options",
						"title" => esc_html__("Min-Max options", "WCSEARCH"),
						"description" => "Example: 1,5,10,15,20 or 0-20",
						"value" => "0-30",
				),
				array(
						"type" => "dependency",
						"name" => "dependency_tax",
						"title" => esc_html__("Dependency", "WCSEARCH"),
						"description" => esc_html__("The field will be dependent from selected tax", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("No dependency", "WCSEARCH"),
						),
				),
				array(
						"type" => "select",
						"name" => "dependency_visibility",
						"title" => esc_html__("Dependency visibility", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("Hidden", "WCSEARCH"),
								"1" => esc_html__("Shaded", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array("dependency_tax" => ""),
				),
		),
		"button" => array(
				array(
						"type" => "string",
						"name" => "text",
						"title" => esc_html__("Button text", "WCSEARCH"),
						"value" => esc_html__("Search", "WCSEARCH"),
				),
		),
		"reset" => array(
				array(
						"type" => "string",
						"name" => "text",
						"title" => esc_html__("Reset text", "WCSEARCH"),
						"value" => esc_html__("Reset", "WCSEARCH"),
				),
		),
		"more_filters" => array(
				array(
						"type" => "string",
						"name" => "text",
						"title" => esc_html__("Text", "WCSEARCH"),
						"value" => esc_html__("More filters", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "open_by_default",
						"title" => esc_html__("Opened by default", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
		),
		"tax" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => esc_html__("Title", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "select",
						"name" => "mode",
						"title" => esc_html__("Search mode", "WCSEARCH"),
						"options" => array(
								"dropdown" => esc_html__("Single dropdown", "WCSEARCH"),
								"dropdown_keywords" => esc_html__("Single dropdown + keywords", "WCSEARCH"),
								"hierarhical_dropdown" => esc_html__("Heirarhical dropdown", "WCSEARCH"),
								"multi_dropdown" => esc_html__("Multi dropdown", "WCSEARCH"),
								"radios" => esc_html__("Radios", "WCSEARCH"),
								"radios_buttons" => esc_html__("Radio buttons", "WCSEARCH"),
								"checkboxes" => esc_html__("Checkboxes", "WCSEARCH"),
								"checkboxes_buttons" => esc_html__("Checkboxes buttons", "WCSEARCH"),
								"range" => esc_html__("Range slider", "WCSEARCH"),
								"single_slider" => esc_html__("Single slider", "WCSEARCH"),
						),
						"value" => "dropdown",
				),
				array(
						"type" => "string",
						"name" => "placeholder",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => "",
						"dependency" => array('mode' => 'dropdown,dropdown_keywords,dropdown_address,multi_dropdown'),
				),
				array(
						"type" => "string",
						"name" => "placeholders",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						//"value" => array(""),
						//"multi" => 1,
						"dependency" => array('mode' => 'hierarhical_dropdown'),
				),
				array(
						"type" => "string",
						"name" => "try_to_search_text",
						"title" => esc_html__("Try to search text", "WCSEARCH"),
						"value" => esc_html__("Try to search", "WCSEARCH"),
						"dependency" => array('mode' => 'dropdown_address,dropdown_keywords'),
				),
				array(
						"type" => "string",
						"name" => "address_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "Los Angeles, US Capitol, Central Park NY",
						"dependency" => array('mode' => 'dropdown_address'),
				),
				array(
						"type" => "string",
						"name" => "keywords_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "sport,business,event",
						"dependency" => array('mode' => 'dropdown_keywords'),
				),
				array(
						"type" => "select",
						"name" => "do_links",
						"title" => esc_html__("Links to products in autocomplete suggestion", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array('mode' => 'dropdown_keywords'),
				),
				array(
						"type" => "select",
						"name" => "do_links_blank",
						"title" => esc_html__("How to open links", "WCSEARCH"),
						"options" => array(
								"blank" => esc_html__("Open in new window", "WCSEARCH"),
								"self" => esc_html__("Open in same window", "WCSEARCH"),
						),
						"value" => "blank",
						"dependency" => array('mode' => 'dropdown_keywords', 'do_links' => '1'),
				),
				array(
						"type" => "select",
						"name" => "relation",
						"title" => esc_html__("Relation", "WCSEARCH"),
						"options" => array(
								"OR" => "OR",
								"AND" => "AND",
						),
						"value" => "OR",
						"dependency" => array('mode' => 'multi_dropdown,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "depth",
						"title" => esc_html__("Max depth level", "WCSEARCH"),
						"options" => array(
								"1" => "1",
								"2" => "2",
								"3" => "3",
								"4" => "4",
						),
						"value" => 1,
						"dependency" => array('mode' => 'dropdown,dropdown_address,dropdown_keywords,multi_dropdown,radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "open_on_click",
						"title" => esc_html__("Open on click", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => 1,
						"dependency" => array('mode' => 'dropdown,dropdown_address,dropdown_keywords'),
				),
				array(
						"type" => "select",
						"name" => "columns",
						"title" => esc_html__("Columns", "WCSEARCH"),
						"options" => array(
								1 => 1,
								2 => 2,
								3 => 3,
								4 => 4,
								5 => 5,
						),
						"value" => 2,
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "string",
						"name" => "height_limit",
						"title" => esc_html__("Cut long-list items by height (in pixels)", "WCSEARCH"),
						"value" => 280,
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "how_to_limit",
						"title" => esc_html__("How to cut long-list items", "WCSEARCH"),
						"options" => array(
								"show_more_less" => esc_html__("Show all/hide and scroll", "WCSEARCH"),
								"use_scroll" => esc_html__("Use only scroll", "WCSEARCH"),
						),
						"value" => "show_more_less",
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "string",
						"name" => "text_open",
						"title" => esc_html__("Text to open new items", "WCSEARCH"),
						"value" => esc_html__("show all"),
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons', 'how_to_limit' => 'show_more_less'),
				),
				array(
						"type" => "string",
						"name" => "text_close",
						"title" => esc_html__("Text to hide", "WCSEARCH"),
						"value" => esc_html__("hide"),
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons', 'how_to_limit' => 'show_more_less'),
				),
				array(
						"type" => "select",
						"name" => "use_pointer",
						"title" => esc_html__("Use floating pointer", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "orderby",
						"title" => esc_html__("Order terms", "WCSEARCH"),
						"options" => array(
								"menu_order" => esc_html__("By default", "WCSEARCH"),
								"name" => esc_html__("By name", "WCSEARCH"),
								"count" => esc_html__("By count", "WCSEARCH"),
						),
						"value" => "menu_order",
						"dependency" => array('mode' => 'dropdown,dropdown_address,dropdown_keywords,hierarhical_dropdown,multi_dropdown,radios,radios_buttons,checkboxes,checkboxes_buttons,range,single_slider'),
				),
				array(
						"type" => "select",
						"name" => "order",
						"title" => esc_html__("Order direction", "WCSEARCH"),
						"options" => array(
								"ASC" => esc_html__("ASC", "WCSEARCH"),
								"DESC" => esc_html__("DESC", "WCSEARCH"),
						),
						"value" => "ASC",
						"dependency" => array(
								'mode' => 'dropdown,dropdown_address,dropdown_keywords,hierarhical_dropdown,multi_dropdown,radios,radios_buttons,checkboxes,checkboxes_buttons,range,single_slider',
								'orderby' => 'name,count',
						),
				),
				array(
						"type" => "select",
						"name" => "hide_empty",
						"title" => esc_html__("Hide empty", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array('mode' => 'dropdown,dropdown_address,dropdown_keywords,hierarhical_dropdown,multi_dropdown,radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "exact_terms",
						"name" => "is_exact_terms",
						"title" => esc_html__("Set specific terms", "WCSEARCH"),
						"description" => esc_html__("Show all terms or select specific (dependent on max depth level)", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("All terms", "WCSEARCH"),
								1 => esc_html__("Specific terms", "WCSEARCH"),
						),
				),
				array(
						"type" => "dependency",
						"name" => "dependency_tax",
						"title" => esc_html__("Dependency", "WCSEARCH"),
						"description" => esc_html__("The field will be dependent from selected tax", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("No dependency", "WCSEARCH"),
						),
				),
				array(
						"type" => "select",
						"name" => "dependency_visibility",
						"title" => esc_html__("Dependency visibility", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("Hidden", "WCSEARCH"),
								"1" => esc_html__("Shaded", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array("dependency_tax" => ""),
				),
				array(
						"type" => "hidden",
						"name" => "terms_options",
						"value" => "",
				),
		),
		"select" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Title", "WCSEARCH"),
						"value" => esc_html__("Title", "WCSEARCH"),
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "select",
						"name" => "mode",
						"title" => esc_html__("Search mode", "WCSEARCH"),
						"options" => array(
								"dropdown" => esc_html__("Single dropdown", "WCSEARCH"),
								"dropdown_keywords" => esc_html__("Single dropdown + keywords", "WCSEARCH"),
								"multi_dropdown" => esc_html__("Multi dropdown", "WCSEARCH"),
								"radios" => esc_html__("Radios", "WCSEARCH"),
								"radios_buttons" => esc_html__("Radio buttons", "WCSEARCH"),
								"checkboxes" => esc_html__("Checkboxes", "WCSEARCH"),
								"checkboxes_buttons" => esc_html__("Checkboxes buttons", "WCSEARCH"),
								"range" => esc_html__("Range slider", "WCSEARCH"),
								"single_slider" => esc_html__("Single slider", "WCSEARCH"),
						),
						"value" => "dropdown",
				),
				array(
						"type" => "string",
						"name" => "try_to_search_text",
						"title" => esc_html__("Try to search text", "WCSEARCH"),
						"value" => esc_html__("Try to search", "WCSEARCH"),
				),
				array(
						"type" => "string",
						"name" => "placeholder",
						"title" => esc_html__("Placeholder", "WCSEARCH"),
						"value" => "",
						"dependency" => array('mode' => 'dropdown,dropdown_keywords,dropdown_address,hierarhical_dropdown,multi_dropdown'),
				),
				array(
						"type" => "string",
						"name" => "address_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "Los Angeles, US Capitol, Central Park NY",
						"dependency" => array('mode' => 'dropdown_address'),
				),
				array(
						"type" => "string",
						"name" => "keywords_suggestions",
						"title" => esc_html__("Try to search", "WCSEARCH"),
						"description" => esc_html__("Comma-separated list of suggestions to try to search", "WCSEARCH"),
						"value" => "sport,business,event",
						"dependency" => array('mode' => 'dropdown_keywords'),
				),
				array(
						"type" => "select",
						"name" => "relation",
						"title" => esc_html__("Relation", "WCSEARCH"),
						"options" => array(
								"OR" => "OR",
								"AND" => "AND",
						),
						"value" => "OR",
						"dependency" => array('mode' => 'multi_dropdown,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "open_on_click",
						"title" => esc_html__("Open on click", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => 1,
						"dependency" => array('mode' => 'dropdown,dropdown_address,dropdown_keywords'),
				),
				array(
						"type" => "select",
						"name" => "columns",
						"title" => esc_html__("Columns", "WCSEARCH"),
						"options" => array(
								1 => 1,
								2 => 2,
								3 => 3,
								4 => 4,
								5 => 5,
						),
						"value" => 2,
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "string",
						"name" => "height_limit",
						"title" => esc_html__("Cut long-list items by height (in pixels)", "WCSEARCH"),
						"value" => 280,
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "how_to_limit",
						"title" => esc_html__("How to cut long-list items", "WCSEARCH"),
						"options" => array(
								"show_more_less" => esc_html__("Show all/hide and scroll", "WCSEARCH"),
								"use_scroll" => esc_html__("Use only scroll", "WCSEARCH"),
						),
						"value" => "show_more_less",
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "string",
						"name" => "text_open",
						"title" => esc_html__("Text to open new items", "WCSEARCH"),
						"value" => esc_html__("show all"),
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons', 'how_to_limit' => 'show_more_less'),
				),
				array(
						"type" => "string",
						"name" => "text_close",
						"title" => esc_html__("Text to hide", "WCSEARCH"),
						"value" => esc_html__("hide"),
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons', 'how_to_limit' => 'show_more_less'),
				),
				array(
						"type" => "select",
						"name" => "use_pointer",
						"title" => esc_html__("Use floating pointer", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
						"dependency" => array('mode' => 'radios,radios_buttons,checkboxes,checkboxes_buttons'),
				),
				array(
						"type" => "select",
						"name" => "orderby",
						"title" => esc_html__("Order terms", "WCSEARCH"),
						"options" => array(
								"menu_order" => esc_html__("By default", "WCSEARCH"),
								"name" => esc_html__("By name", "WCSEARCH"),
								"count" => esc_html__("By count", "WCSEARCH"),
						),
						"value" => "menu_order",
						"dependency" => array('mode' => 'dropdown,dropdown_keywords,multi_dropdown,radios,radios_buttons,checkboxes,checkboxes_buttons,range,single_slider'),
				),
				array(
						"type" => "select",
						"name" => "order",
						"title" => esc_html__("Order direction", "WCSEARCH"),
						"options" => array(
								"ASC" => esc_html__("ASC", "WCSEARCH"),
								"DESC" => esc_html__("DESC", "WCSEARCH"),
						),
						"value" => "ASC",
						"dependency" => array(
								'mode' => 'dropdown,dropdown_keywords,multi_dropdown,radios,radios_buttons,checkboxes,checkboxes_buttons,range,single_slider',
								'orderby' => 'name,count',
						),
				),
				array(
						"type" => "select",
						"name" => "hide_empty",
						"title" => esc_html__("Hide empty", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "1",
				),
				array(
						"type" => "exact_terms",
						"name" => "is_exact_terms",
						"title" => esc_html__("Set specific terms", "WCSEARCH"),
						"description" => esc_html__("Show all terms or select specific (dependent on max depth level)", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("All terms", "WCSEARCH"),
								1 => esc_html__("Specific terms", "WCSEARCH"),
						),
				),
				array(
						"type" => "dependency",
						"name" => "dependency_tax",
						"title" => esc_html__("Dependency", "WCSEARCH"),
						"description" => esc_html__("The field will be dependent from selected tax", "WCSEARCH"),
						"options" => array(
								0 => esc_html__("No dependency", "WCSEARCH"),
						),
				),
				array(
						"type" => "select",
						"name" => "dependency_visibility",
						"title" => esc_html__("Dependency visibility", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("Hidden", "WCSEARCH"),
								"1" => esc_html__("Shaded", "WCSEARCH"),
						),
						"value" => "1",
						"dependency" => array("dependency_tax" => ""),
				),
		),
		"featured" => array(
				array(
						"type" => "string",
						"name" => "label",
						"title" => esc_html__("Label text", "WCSEARCH"),
						"value" => esc_html__("featured"),
				),
				array(
						"type" => "select",
						"name" => "align",
						"title" => esc_html__("Align", "WCSEARCH"),
						"options" => array(
								"left" => esc_html__("Left", "WCSEARCH"),
								"center" => esc_html__("Center", "WCSEARCH"),
								"right" => esc_html__("Right", "WCSEARCH"),
						),
						"value" => "left",
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
		),
		"instock" => array(
				array(
						"type" => "string",
						"name" => "label",
						"title" => esc_html__("Label text", "WCSEARCH"),
						"value" => esc_html__("in stock"),
				),
				array(
						"type" => "select",
						"name" => "align",
						"title" => esc_html__("Align", "WCSEARCH"),
						"options" => array(
								"left" => esc_html__("Left", "WCSEARCH"),
								"center" => esc_html__("Center", "WCSEARCH"),
								"right" => esc_html__("Right", "WCSEARCH"),
						),
						"value" => "left",
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
		),
		"onsale" => array(
				array(
						"type" => "string",
						"name" => "label",
						"title" => esc_html__("Label text", "WCSEARCH"),
						"value" => esc_html__("on sale"),
				),
				array(
						"type" => "select",
						"name" => "align",
						"title" => esc_html__("Align", "WCSEARCH"),
						"options" => array(
								"left" => esc_html__("Left", "WCSEARCH"),
								"center" => esc_html__("Center", "WCSEARCH"),
								"right" => esc_html__("Right", "WCSEARCH"),
						),
						"value" => "left",
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
		),
		"ratings" => array(
				array(
						"type" => "string",
						"name" => "title",
						"title" => esc_html__("Label text", "WCSEARCH"),
						"value" => esc_html__("By ratings"),
				),
				array(
						"type" => "select",
						"name" => "visible_status",
						"title" => esc_html__("Visible", "WCSEARCH"),
						"options" => array(
								"always_opened" => esc_html__("Always opened", "WCSEARCH"),
								"opened" => esc_html__("Opened", "WCSEARCH"),
								"closed" => esc_html__("Closed", "WCSEARCH"),
								"always_closed" => esc_html__("Always closed", "WCSEARCH"),
								"more_filters" => esc_html__("In 'more filters' section", "WCSEARCH"),
						),
						"value" => "always_opened",
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
				array(
						"type" => "color",
						"name" => "stars_color",
						"title" => esc_html__("Stars color", "WCSEARCH"),
						"value" => "#FFB300",
				),
		),
		"hours" => array(
				array(
						"type" => "string",
						"name" => "label",
						"title" => esc_html__("Label text", "WCSEARCH"),
						"value" => esc_html__("open now"),
				),
				array(
						"type" => "select",
						"name" => "display",
						"title" => esc_html__("Display as", "WCSEARCH"),
						"options" => array(
								"checkbox" => esc_html__("Checkbox", "WCSEARCH"),
								"button" => esc_html__("Button", "WCSEARCH"),
						),
						"value" => "checkbox",
				),
				array(
						"type" => "select",
						"name" => "align",
						"title" => esc_html__("Align", "WCSEARCH"),
						"options" => array(
								"left" => esc_html__("Left", "WCSEARCH"),
								"center" => esc_html__("Center", "WCSEARCH"),
								"right" => esc_html__("Right", "WCSEARCH"),
						),
						"value" => "left",
						"dependency" => array("display" => "checkbox"),
				),
				array(
						"type" => "select",
						"name" => "counter",
						"title" => esc_html__("Show counter", "WCSEARCH"),
						"options" => array(
								"0" => esc_html__("No", "WCSEARCH"),
								"1" => esc_html__("Yes", "WCSEARCH"),
						),
						"value" => "0",
				),
		),
);


add_filter("init", "wcsearch_set_default_model_settings", 1);
add_filter("admin_init", "wcsearch_set_default_model_settings", 1);
function wcsearch_set_default_model_settings() {
	global $wcsearch_default_model_settings;
	
	$wcsearch_default_model_settings = array(
			'model' => array(
					'placeholders' => array(
							array(
									"columns" => 1,
									"rows" => 1,
									"input" => "",
							),
					),
			),
			'columns_num' => 1,
			'bg_color' => "",
			'bg_transparency' => 100,
			'text_color' => "#666666",
			'elements_color' => "#428BCA",
			'elements_color_secondary' => "#275379",
			'use_overlay' => 0,
			'on_shop_page' => 0,
			'auto_submit' => 0,
			'use_border' => 1,
			'scroll_to' => '', // products
			'sticky_scroll' => 0,
			'sticky_scroll_toppadding' => 0,
			'use_ajax' => 1,
			'target_url' => '',
			'used_by' => wcsearch_get_default_used_by(), // wc, w2dc, w2gm, w2mb
		
	);
}

add_filter("admin_init", "wcsearch_filter_model_options");
function wcsearch_filter_model_options() {
	global $wcsearch_model_options;

	$taxes = wcsearch_get_all_taxonomies();
	$tax_names = wcsearch_get_all_taxonomies_names();

	foreach ($wcsearch_model_options AS $type=>$options) {

		// add taxonomies in dependency fields
		//
		// "categories" instead of "w2dc-category",
		// "locations" instead of "w2dc-location",
		// "tags" instead of "w2dc-tag"
		foreach ($options AS $key=>$option) {
			if ($option['type'] == 'dependency') {
				foreach ($taxes AS $tax_slug=>$tax_name) {
					$wcsearch_model_options[$type][$key]['options'][$tax_name] = $tax_names[$tax_slug];
				}
			}
		}

		// add "Single dropdown + address" option in mode
		if (wcsearch_geocode_functions()) {
			if ($type == 'tax') {
				foreach ($options AS $key=>$option) {
					if ($option['name'] == 'mode') {
						$arr = $wcsearch_model_options[$type][$key]["options"];
						
						$arr = array_slice($arr, 0, 2, true) +
						array("dropdown_address" => esc_html__("Single dropdown + address", "WCSEARCH")) +
						array_slice($arr, 2, count($arr)-2, true);

						$wcsearch_model_options[$type][$key]["options"] = $arr;
					}
				}
			}
		}
	}
}

class wcsearch_search_forms_manager {
	
	public function __construct() {
		add_action('add_meta_boxes', array($this, 'addSearchFormMetabox'));
		
		add_filter('manage_'.WCSEARCH_FORM_TYPE.'_posts_columns', array($this, 'add_wcsearch_table_columns'));
		add_filter('manage_'.WCSEARCH_FORM_TYPE.'_posts_custom_column', array($this, 'manage_wcsearch_table_rows'), 10, 2);
		
		add_filter('post_row_actions', array($this, 'duplicate_form_link'), 10, 2);
		add_action('admin_action_wcsearch_duplicate_form', array($this, 'duplicate_form'));
		
		add_action('wp_ajax_wcsearch_tax_dropdowns_hook', 'wcsearch_tax_dropdowns_updateterms');
		add_action('wp_ajax_nopriv_wcsearch_tax_dropdowns_hook', 'wcsearch_tax_dropdowns_updateterms');
		
		if (isset($_POST['submit']) && isset($_POST['post_type']) && $_POST['post_type'] == WCSEARCH_FORM_TYPE) {
			add_action('save_post_' . WCSEARCH_FORM_TYPE, array($this, 'saveForm'), 10, 3);
		}
	}
	
	public function duplicate_form_link($actions, $post) {
		if ($post->post_type == WCSEARCH_FORM_TYPE) {
			$actions['duplicate'] = '<a href="' . wp_nonce_url('admin.php?action=wcsearch_duplicate_form&post=' . $post->ID, basename(__FILE__), 'duplicate_nonce') . '" title="' . __("Make duplicate", "W2DC") . '">' . __("Make duplicate", "W2DC") . '</a>';
		}
	
		return $actions;
	}
	
	public function duplicate_form() {
		global $wpdb;
	
		if (empty($_GET['post'])) {
			wp_die('No post to duplicate has been supplied!');
		}
	
		if (!isset($_GET['duplicate_nonce']) || !wp_verify_nonce($_GET['duplicate_nonce'], basename(__FILE__))) {
			return;
		}
	
		$post_id = sanitize_text_field($_GET['post']);
		$post = get_post($post_id);
	
		$current_user = wp_get_current_user();
		$new_post_author = $current_user->ID;
	
		if (isset($post) && $post != null) {
			$args = array(
					'comment_status' => $post->comment_status,
					'ping_status'    => $post->ping_status,
					'post_author'    => $new_post_author,
					'post_content'   => $post->post_content,
					'post_excerpt'   => $post->post_excerpt,
					'post_name'      => $post->post_name . "-duplicate",
					'post_parent'    => $post->post_parent,
					'post_password'  => $post->post_password,
					'post_status'    => 'publish',
					'post_title'     => $post->post_title . " (duplicate)",
					'post_type'      => $post->post_type,
					'to_ping'        => $post->to_ping,
					'menu_order'     => $post->menu_order
			);
			$new_post_id = wp_insert_post( $args );
				
			$post_meta_infos = $wpdb->get_results($wpdb->prepare("SELECT meta_key, meta_value FROM $wpdb->postmeta WHERE post_id=%d", $post_id));
			if (count($post_meta_infos)) {
				$sql_query = "INSERT INTO $wpdb->postmeta (post_id, meta_key, meta_value) ";
				foreach ($post_meta_infos as $meta_info) {
					$meta_key = $meta_info->meta_key;
					if ($meta_key == '_wp_old_slug') {
						continue;
					}
					$meta_value = addslashes($meta_info->meta_value);
					$sql_query_sel[]= "SELECT $new_post_id, '$meta_key', '$meta_value'";
				}
				$sql_query.= implode(" UNION ALL ", $sql_query_sel);
				$wpdb->query($sql_query);
			}
				
			wp_redirect(admin_url('post.php?action=edit&post=' . $new_post_id));
			die();
		} else {
			wp_die('Post creation failed, could not find original post: ' . $post_id);
		}
	}
	
	public function addSearchFormMetabox($post_type) {
		if ($post_type == WCSEARCH_FORM_TYPE) {
			remove_meta_box('submitdiv', WCSEARCH_FORM_TYPE, 'side');
			
			add_meta_box('wcsearch_form',
			__('Search Form', 'WCSEARCH'),
			array($this, 'searchFormMetabox'),
			WCSEARCH_FORM_TYPE,
			'normal',
			'high');
		}
	}
	
	public function searchFormMetabox($post) {
		global $wcsearch_default_model_settings;
	
		wp_enqueue_script('jquery-ui-draggable');
		wp_enqueue_script('jquery-ui-sortable');
		wp_enqueue_script('jquery-ui-droppable');
		wp_enqueue_script('jquery-ui-slider');
		wp_enqueue_script('jquery-ui-datepicker');
		wp_enqueue_style('wp-color-picker');
		wp_enqueue_script('wp-color-picker');
		
		$model = get_post_meta($post->ID, '_model', true);
		
		$search_form_data = array();
		if (!$model) {
			// default model
			foreach ($wcsearch_default_model_settings AS $setting=>$value) {
				$search_form_data[$setting] = $value;
			}
			
			$model = $search_form_data['model'];
		} else {
			$model = json_decode($model, true);
			
			foreach ($wcsearch_default_model_settings AS $setting=>$value) {
				if (metadata_exists('post', $post->ID, '_'.$setting)) {
					$search_form_data[$setting] = get_post_meta($post->ID, '_'.$setting, true);
				} else {
					$search_form_data[$setting] = $wcsearch_default_model_settings[$setting];
				}
			}
		}
		
		if (wcsearch_getValue($_GET, 'export')) {
			echo '<textarea style="width: 100%; height: 500px;">';
			echo "{";
			$key_value_pair = array();
			foreach ($search_form_data AS $setting=>$val) {
				$key_value_pair[] = '"'.esc_attr($setting).'":"'.addslashes($val).'"';
			}
			echo implode(",", $key_value_pair);
			echo "}";
			echo '</textarea>';
		}
		
		$search_form_model = new wcsearch_search_form_model($model['placeholders'], $search_form_data['used_by']);
		
		wcsearch_renderTemplate('search_form_model.tpl.php',
			array(
				'wcsearch_model' => $model,
				'search_form_model' => $search_form_model,
				'search_form_data' => $search_form_data,
			)
		);
	}
	
	public function saveForm($post_ID, $post, $update) {
		global $wcsearch_default_model_settings;
		
		foreach ($wcsearch_default_model_settings AS $setting=>$value) {
			update_post_meta($post_ID, '_'.$setting, wcsearch_getValue($_POST, $setting));
		}
	}
	
	public function add_wcsearch_table_columns($columns) {
		global $wcsearch_instance;
	
		$wcsearch_columns['wcsearch_shortcode'] = __('Shortcode', 'WCSEARCH');
	
		return array_slice($columns, 0, 2, true) + $wcsearch_columns + array_slice($columns, 2, count($columns)-2, true);
	}
	
	public function manage_wcsearch_table_rows($column, $post_id) {
		switch ($column) {
			case "wcsearch_shortcode":
				echo '['.WCSEARCH_MAIN_SHORTCODE.' id=' . esc_attr($post_id) . ']';
			break;
		}
	}
}

?>
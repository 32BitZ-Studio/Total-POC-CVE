<?php

/**
 * After listing was loaded
 * 
*/
add_filter('w2dc_listing_loading', 'w2dc_listing_loading');
function w2dc_listing_loading($listing) {

	return $listing;
}

/**
 * Listing after submition
 * addons/w2dc_fsubmit/classes/submit_controller.php
 * 
 */
add_filter('w2dc_listing_creation_front', 'w2dc_listing_creation_front');
function w2dc_listing_creation_front($listing) {

	return $listing;
}

/**
 * Redirection to any URL
 * addons/w2dc_fsubmit/classes/submit_controller.php
 * 
 */
add_filter('w2dc_redirect_after_submit', 'w2dc_redirect_after_submit');
function w2dc_redirect_after_submit($redirect_to) {

	return $redirect_to;
}

/**
 * Change template of frontend pages
 * classes/shortcodes/directory_controller.php
 * 
 * example to change listing single template according to its level
 * if (!empty($controller->listing) && $controller->listing->level->id == 1) {
 * 		$template = 'frontend/listing_single_1_level.tpl.php';
 * }
 * 
 */
add_filter('w2dc_frontend_controller_template', 'w2dc_frontend_controller_template', 10, 2);
function w2dc_frontend_controller_template($template, $controller) {

	return $template;
}

/**
 * CSS classes on a listing on excerpt pages
 */
add_filter('w2dc_listing_classes', 'w2dc_listing_classes', 10, 2);
function w2dc_listing_classes($classes, $listing) {

	return $classes;
}

/**
 * CSS classes of a content field
 * 
 */
add_filter('w2dc_content_field_classes', 'w2dc_content_field_classes', 10, 2);
function w2dc_content_field_classes($classes, $content_field) {

	return $classes;
}
/**
 * CSS classes of a content fields group
 * 
 */
add_filter('w2dc_content_fields_group_classes', 'w2dc_content_fields_group_classes', 10, 2);
function w2dc_content_fields_group_classes($classes, $group) {

	return $classes;
}

/**
 * path to template to display a content field
 * 
 * content_fields/fields/address_output.tpl.php
 * or
 * content_fields/fields/address_output_%ID%.tpl.php - where %ID% is the ID of content field
 * 
 */
add_filter('w2dc_content_field_output_template', 'w2dc_content_field_output_template', 10, 4);
function w2dc_content_field_output_template($template, $content_field, $listing, $group) {

	return $template;
}


// Before email sending
add_filter('w2dc_mail_email', 'w2dc_mail_email', 10, 4);
function w2dc_mail_email($email, $subject, $body, $headers) {

	return $email;
}
add_filter('w2dc_mail_subject', 'w2dc_mail_subject', 10, 4);
function w2dc_mail_subject($subject, $email, $body, $headers) {

	return $subject;
}
add_filter('w2dc_mail_body', 'w2dc_mail_body', 10, 4);
function w2dc_mail_body($body, $email, $subject, $headers) {

	return $body;
}
add_filter('w2dc_mail_headers', 'w2dc_mail_headers', 10, 4);
function w2dc_mail_headers($headers, $email, $subject, $body) {

	return $headers;
}


// delete listing or place in the trash (default true)
add_filter('w2dc_delete_or_trash_listing', 'w2dc_delete_or_trash_listing', 10, 2);
function w2dc_delete_or_trash_listing($force_delete, $listing_id) {

	return $force_delete;
}

// delete listing attachments or place in the trash (default false)
add_filter('w2dc_force_delete_attachment', 'w2dc_force_delete_attachment', 10, 2);
function w2dc_force_delete_attachment($force_delete, $listing_id) {

	return $force_delete;
}




/*
 * 
 * Output of var_dump($listing);
 * 
 * 
 * object(w2dc_listing)#3853) (19 {
  ["post"]=>
  object(WP_Post)#3922 (25) {
    ["ID"]=>
    int(70)
    ["post_author"]=>
    string(1) "2"
    ["post_date"]=>
    string(19) "2013-06-30 13:26:46"
    ["post_date_gmt"]=>
    string(19) "2013-06-30 13:26:46"
    ["post_content"]=>
    string(925) ""
    ["post_title"]=>
    string(14) "Avenue florist"
    ["post_excerpt"]=>
    string(131) "Nulla gravida commodo est, sed euismod augue dictum ac. Maecenas non libero ante. Suspendisse non tellus nisl, vitae sodales neque."
    ["post_status"]=>
    string(7) "publish"
    ["comment_status"]=>
    string(4) "open"
    ["ping_status"]=>
    string(6) "closed"
    ["post_password"]=>
    string(0) ""
    ["post_name"]=>
    string(14) "avenue-florist"
    ["to_ping"]=>
    string(0) ""
    ["pinged"]=>
    string(0) ""
    ["post_modified"]=>
    string(19) "2020-02-27 19:23:32"
    ["post_modified_gmt"]=>
    string(19) "2020-02-27 13:23:32"
    ["post_content_filtered"]=>
    string(0) ""
    ["post_parent"]=>
    int(0)
    ["guid"]=>
    string(43) "http://wp/?post_type=w2dc_listing&#038;p=70"
    ["menu_order"]=>
    int(0)
    ["post_type"]=>
    string(12) "w2dc_listing"
    ["post_mime_type"]=>
    string(0) ""
    ["comment_count"]=>
    string(1) "6"
    ["filter"]=>
    string(3) "raw"
    ["robotsmeta"]=>
    NULL
  }
  ["directory"]=>
  object(w2dc_directory)#1492 (12) {
    ["id"]=>
    string(1) "1"
    ["url"]=>
    string(10) "http://wp/"
    ["name"]=>
    string(8) "Listings"
    ["single"]=>
    string(7) "listing"
    ["plural"]=>
    string(8) "listings"
    ["listing_slug"]=>
    string(7) "listing"
    ["category_slug"]=>
    string(16) "listing-category"
    ["location_slug"]=>
    string(13) "listing-place"
    ["tag_slug"]=>
    string(11) "listing-tag"
    ["categories"]=>
    array(0) {
    }
    ["locations"]=>
    array(0) {
    }
    ["levels"]=>
    array(0) {
    }
  }
  ["level"]=>
  object(w2dc_level)#1484 (32) {
    ["id"]=>
    string(1) "2"
    ["order_num"]=>
    string(1) "2"
    ["name"]=>
    string(8) "Featured"
    ["description"]=>
    string(251) "<b>Plan description:</b>
- this level has eternal active period
- listings have featured status and will be sticky to the top of all lists
- users may select up to 10 categories and 3 locations
- google maps enabled
- custom markers on google map"
    ["who_can_view"]=>
    array(0) {
    }
    ["active_interval"]=>
    string(1) "0"
    ["active_period"]=>
    string(0) ""
    ["eternal_active_period"]=>
    string(1) "1"
    ["change_level_id"]=>
    string(1) "0"
    ["listings_in_package"]=>
    string(1) "1"
    ["featured"]=>
    string(1) "1"
    ["listings_own_page"]=>
    string(1) "1"
    ["nofollow"]=>
    string(1) "0"
    ["raiseup_enabled"]=>
    string(1) "1"
    ["sticky"]=>
    string(1) "1"
    ["categories_number"]=>
    string(2) "10"
    ["unlimited_categories"]=>
    string(1) "0"
    ["tags_number"]=>
    string(1) "0"
    ["unlimited_tagss"]=>
    int(1)
    ["locations_number"]=>
    string(2) "30"
    ["map"]=>
    string(1) "1"
    ["map_markers"]=>
    string(1) "1"
    ["logo_enabled"]=>
    string(1) "1"
    ["images_number"]=>
    string(2) "10"
    ["videos_number"]=>
    string(1) "5"
    ["categories"]=>
    array(0) {
    }
    ["locations"]=>
    array(0) {
    }
    ["content_fields"]=>
    array(19) {
      [0]=>
      int(20)
      [1]=>
      int(21)
      [2]=>
      int(22)
      [3]=>
      int(5)
      [4]=>
      int(19)
      [5]=>
      int(4)
      [6]=>
      int(3)
      [7]=>
      int(7)
      [9]=>
      int(8)
      [10]=>
      int(17)
      [11]=>
      int(11)
      [12]=>
      int(13)
      [13]=>
      int(14)
      [14]=>
      int(15)
      [15]=>
      int(6)
      [16]=>
      int(18)
      [18]=>
      string(2) "24"
      [19]=>
      string(2) "16"
      [20]=>
      string(1) "2"
    }
    ["upgrade_meta"]=>
    array(4) {
      [4]=>
      array(3) {
        ["price"]=>
        int(0)
        ["disabled"]=>
        bool(false)
        ["raiseup"]=>
        bool(false)
      }
      [1]=>
      array(3) {
        ["price"]=>
        string(3) "3.6"
        ["disabled"]=>
        bool(false)
        ["raiseup"]=>
        bool(false)
      }
      [2]=>
      array(3) {
        ["price"]=>
        int(0)
        ["disabled"]=>
        bool(true)
        ["raiseup"]=>
        bool(true)
      }
      [3]=>
      array(3) {
        ["price"]=>
        string(1) "4"
        ["disabled"]=>
        bool(false)
        ["raiseup"]=>
        bool(false)
      }
    }
    ["unlimited_tags"]=>
    string(1) "1"
    ["price"]=>
    string(3) "9.1"
    ["raiseup_price"]=>
    string(4) "11.5"
  }
  ["expiration_date"]=>
  NULL
  ["order_date"]=>
  string(10) "1472978541"
  ["listing_created"]=>
  string(1) "1"
  ["status"]=>
  string(6) "active"
  ["categories"]=>
  array(0) {
  }
  ["locations"]=>
  array(3) {
    [0]=>
    object(w2dc_location)#3849 (13) {
      ["id"]=>
      string(4) "9962"
      ["post_id"]=>
      int(70)
      ["selected_location"]=>
      string(3) "190"
      ["address_line_1"]=>
      string(0) ""
      ["address_line_2"]=>
      string(0) ""
      ["zip_or_postal_index"]=>
      string(0) ""
      ["additional_info"]=>
      string(0) ""
      ["manual_coords"]=>
      string(1) "0"
      ["map_coords_1"]=>
      string(9) "34.013401"
      ["map_coords_2"]=>
      string(11) "-117.690102"
      ["map_icon_file"]=>
      string(19) "_new/Disability.png"
      ["map_icon_color"]=>
      bool(false)
      ["map_icon_manually_selected"]=>
      bool(false)
    }
    [1]=>
    object(w2dc_location)#3848 (13) {
      ["id"]=>
      string(4) "9963"
      ["post_id"]=>
      int(70)
      ["selected_location"]=>
      string(3) "195"
      ["address_line_1"]=>
      string(0) ""
      ["address_line_2"]=>
      string(0) ""
      ["zip_or_postal_index"]=>
      string(0) ""
      ["additional_info"]=>
      string(0) ""
      ["manual_coords"]=>
      string(1) "1"
      ["map_coords_1"]=>
      string(9) "34.113087"
      ["map_coords_2"]=>
      string(11) "-118.189613"
      ["map_icon_file"]=>
      string(19) "_new/Disability.png"
      ["map_icon_color"]=>
      bool(false)
      ["map_icon_manually_selected"]=>
      bool(false)
    }
    [2]=>
    object(w2dc_location)#3846 (13) {
      ["id"]=>
      string(4) "9964"
      ["post_id"]=>
      int(70)
      ["selected_location"]=>
      string(3) "193"
      ["address_line_1"]=>
      string(0) ""
      ["address_line_2"]=>
      string(0) ""
      ["zip_or_postal_index"]=>
      string(0) ""
      ["additional_info"]=>
      string(0) ""
      ["manual_coords"]=>
      string(1) "1"
      ["map_coords_1"]=>
      string(9) "34.031811"
      ["map_coords_2"]=>
      string(11) "-118.270187"
      ["map_icon_file"]=>
      string(19) "_new/Disability.png"
      ["map_icon_color"]=>
      bool(false)
      ["map_icon_manually_selected"]=>
      bool(false)
    }
  }
  ["content_fields"]=>
  array(18) {
    [24]=>
    object(w2dc_content_field_phone)#3847 (33) {
      ["max_length"]=>
      string(3) "255"
      ["regex"]=>
      string(0) ""
      ["phone_mode"]=>
      string(8) "whatsapp"
      ["can_be_searched":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(2) "24"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(1) "1"
      ["name"]=>
      string(17) "Test phone number"
      ["slug"]=>
      string(17) "test_phone_number"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(5) "phone"
      ["icon_image"]=>
      string(16) "w2dc-fa-dribbble"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(4) {
        [0]=>
        string(1) "4"
        [1]=>
        string(1) "1"
        [2]=>
        string(1) "2"
        [3]=>
        string(1) "3"
      }
      ["options"]=>
      array(3) {
        ["max_length"]=>
        string(3) "255"
        ["regex"]=>
        string(0) ""
        ["phone_mode"]=>
        string(8) "whatsapp"
      }
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["value"]=>
      string(12) "+79069910777"
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [21]=>
    object(w2dc_content_field_email)#3852 (30) {
      ["can_be_ordered":protected]=>
      bool(false)
      ["id"]=>
      string(2) "21"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(1) "3"
      ["name"]=>
      string(4) "test"
      ["slug"]=>
      string(4) "test"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(5) "email"
      ["icon_image"]=>
      string(0) ""
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(3) {
        [0]=>
        string(1) "4"
        [1]=>
        string(1) "1"
        [2]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["value"]=>
      string(0) ""
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [22]=>
    object(w2dc_content_field_string)#3843 (32) {
      ["max_length"]=>
      int(255)
      ["regex"]=>
      NULL
      ["can_be_searched":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(2) "22"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(1) "4"
      ["name"]=>
      string(5) "tes 2"
      ["slug"]=>
      string(5) "tes_2"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(6) "string"
      ["icon_image"]=>
      string(0) ""
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["value"]=>
      string(0) ""
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [18]=>
    object(w2dc_content_field_hours)#3842 (32) {
      ["hours_clock"]=>
      string(2) "12"
      ["week_days"]=>
      array(7) {
        [0]=>
        string(3) "sun"
        [1]=>
        string(3) "mon"
        [2]=>
        string(3) "tue"
        [3]=>
        string(3) "wed"
        [4]=>
        string(3) "thu"
        [5]=>
        string(3) "fri"
        [6]=>
        string(3) "sat"
      }
      ["can_be_required":protected]=>
      bool(false)
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["id"]=>
      string(2) "18"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(1) "6"
      ["name"]=>
      string(13) "Opening Hours"
      ["slug"]=>
      string(13) "opening_hours"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(5) "hours"
      ["icon_image"]=>
      string(15) "w2dc-fa-clock-o"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      array(1) {
        ["hours_clock"]=>
        string(2) "12"
      }
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "5"
      ["value"]=>
      array(21) {
        ["sun_from"]=>
        string(0) ""
        ["sun_to"]=>
        string(0) ""
        ["sun_closed"]=>
        string(0) ""
        ["mon_from"]=>
        string(0) ""
        ["mon_to"]=>
        string(0) ""
        ["mon_closed"]=>
        string(0) ""
        ["tue_from"]=>
        string(0) ""
        ["tue_to"]=>
        string(0) ""
        ["tue_closed"]=>
        string(1) "1"
        ["wed_from"]=>
        string(0) ""
        ["wed_to"]=>
        string(0) ""
        ["wed_closed"]=>
        string(0) ""
        ["thu_from"]=>
        string(0) ""
        ["thu_to"]=>
        string(0) ""
        ["thu_closed"]=>
        string(0) ""
        ["fri_from"]=>
        string(0) ""
        ["fri_to"]=>
        string(0) ""
        ["fri_closed"]=>
        string(0) ""
        ["sat_from"]=>
        string(0) ""
        ["sat_to"]=>
        string(0) ""
        ["sat_closed"]=>
        string(0) ""
      }
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [5]=>
    object(w2dc_content_field_categories)#3841 (30) {
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_categories":protected]=>
      bool(false)
      ["is_slug":protected]=>
      bool(false)
      ["id"]=>
      string(1) "5"
      ["is_core_field"]=>
      string(1) "1"
      ["order_num"]=>
      string(1) "7"
      ["name"]=>
      string(15) "Categories list"
      ["slug"]=>
      string(15) "categories_list"
      ["description"]=>
      string(27) "Categories tree description"
      ["type"]=>
      string(10) "categories"
      ["icon_image"]=>
      string(0) ""
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["value"]=>
      NULL
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [4]=>
    object(w2dc_content_field_content)#3840 (30) {
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_categories":protected]=>
      bool(false)
      ["is_slug":protected]=>
      bool(false)
      ["id"]=>
      string(1) "4"
      ["is_core_field"]=>
      string(1) "1"
      ["order_num"]=>
      string(1) "8"
      ["name"]=>
      string(11) "Description"
      ["slug"]=>
      string(7) "content"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(7) "content"
      ["icon_image"]=>
      string(0) ""
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "3"
      ["value"]=>
      NULL
      ["can_be_required":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [19]=>
    object(w2dc_content_field_fileupload)#3839 (34) {
      ["use_text"]=>
      int(1)
      ["default_text"]=>
      string(13) "uploaded file"
      ["use_default_text"]=>
      int(1)
      ["allowed_mime_types"]=>
      array(6) {
        [0]=>
        string(6) "images"
        [1]=>
        string(3) "txt"
        [2]=>
        string(3) "pdf"
        [3]=>
        string(3) "avi"
        [4]=>
        string(3) "mp4"
        [5]=>
        string(3) "mpg"
      }
      ["value"]=>
      array(2) {
        ["id"]=>
        string(5) "18368"
        ["text"]=>
        string(13) "uploaded file"
      }
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(2) "19"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(1) "9"
      ["name"]=>
      string(11) "File upload"
      ["slug"]=>
      string(11) "file_upload"
      ["description"]=>
      string(64) "Allowed files: images files (JPG, PNG, GIF), TXT, PDF, AVI, MPG."
      ["type"]=>
      string(10) "fileupload"
      ["icon_image"]=>
      string(0) ""
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(3) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
        [2]=>
        string(1) "3"
      }
      ["options"]=>
      array(4) {
        ["use_text"]=>
        int(1)
        ["default_text"]=>
        string(13) "uploaded file"
        ["use_default_text"]=>
        int(1)
        ["allowed_mime_types"]=>
        array(6) {
          [0]=>
          string(6) "images"
          [1]=>
          string(3) "txt"
          [2]=>
          string(3) "pdf"
          [3]=>
          string(3) "avi"
          [4]=>
          string(3) "mp4"
          [5]=>
          string(3) "mpg"
        }
      }
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [3]=>
    object(w2dc_content_field_address)#3838 (30) {
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_categories":protected]=>
      bool(false)
      ["is_slug":protected]=>
      bool(false)
      ["id"]=>
      string(1) "3"
      ["is_core_field"]=>
      string(1) "1"
      ["order_num"]=>
      string(2) "10"
      ["name"]=>
      string(7) "Address"
      ["slug"]=>
      string(7) "address"
      ["description"]=>
      string(16) "test description"
      ["type"]=>
      string(7) "address"
      ["icon_image"]=>
      string(18) "w2dc-fa-map-marker"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "2"
      ["value"]=>
      NULL
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [7]=>
    object(w2dc_content_field_phone)#3837 (33) {
      ["max_length"]=>
      int(255)
      ["regex"]=>
      NULL
      ["phone_mode"]=>
      string(5) "phone"
      ["can_be_searched":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(1) "7"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "11"
      ["name"]=>
      string(5) "Phone"
      ["slug"]=>
      string(5) "phone"
      ["description"]=>
      string(42) "Enter phone in such format: (xxx) xxx-xxxx"
      ["type"]=>
      string(5) "phone"
      ["icon_image"]=>
      string(13) "w2dc-fa-phone"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "2"
      ["value"]=>
      string(14) "(123) 123-4444"
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "1"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [16]=>
    object(w2dc_content_field_datetime)#3836 (31) {
      ["is_time"]=>
      int(1)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["can_be_searched":protected]=>
      bool(true)
      ["id"]=>
      string(2) "16"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "12"
      ["name"]=>
      string(10) "Event Date"
      ["slug"]=>
      string(10) "event_date"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(8) "datetime"
      ["icon_image"]=>
      string(16) "w2dc-fa-calendar"
      ["is_required"]=>
      string(1) "1"
      ["is_ordered"]=>
      string(1) "1"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(4) {
        [0]=>
        string(1) "4"
        [1]=>
        string(1) "1"
        [2]=>
        string(1) "2"
        [3]=>
        string(1) "3"
      }
      ["options"]=>
      array(1) {
        ["is_time"]=>
        int(1)
      }
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "4"
      ["value"]=>
      array(4) {
        ["date_start"]=>
        string(10) "1539216000"
        ["date_end"]=>
        string(10) "1539216000"
        ["hour"]=>
        string(2) "00"
        ["minute"]=>
        string(2) "00"
      }
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "1"
      ["advanced_search_form"]=>
      string(1) "1"
    }
    [8]=>
    object(w2dc_content_field_textarea)#3835 (33) {
      ["max_length"]=>
      string(3) "550"
      ["html_editor"]=>
      int(1)
      ["do_shortcodes"]=>
      int(1)
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["can_be_searched":protected]=>
      bool(true)
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(1) "8"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "13"
      ["name"]=>
      string(22) "Additional description"
      ["slug"]=>
      string(22) "additional_description"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(8) "textarea"
      ["icon_image"]=>
      string(16) "w2dc-fa-list-alt"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      array(3) {
        ["max_length"]=>
        string(3) "550"
        ["html_editor"]=>
        int(1)
        ["do_shortcodes"]=>
        int(1)
      }
      ["search_options"]=>
      array(1) {
        ["search_input_mode"]=>
        string(8) "keywords"
      }
      ["group_id"]=>
      string(1) "4"
      ["value"]=>
      string(7) "1
2
3"
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "1"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [17]=>
    object(w2dc_content_field_price)#3834 (36) {
      ["is_integer"]=>
      bool(false)
      ["currency_symbol"]=>
      string(1) "$"
      ["decimal_separator"]=>
      string(1) ","
      ["thousands_separator"]=>
      string(1) " "
      ["symbol_position"]=>
      string(1) "1"
      ["hide_decimals"]=>
      string(1) "0"
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["can_be_searched":protected]=>
      bool(true)
      ["id"]=>
      string(2) "17"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "14"
      ["name"]=>
      string(5) "Price"
      ["slug"]=>
      string(5) "price"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(5) "price"
      ["icon_image"]=>
      string(14) "w2dc-fa-dollar"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "1"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      array(5) {
        ["currency_symbol"]=>
        string(1) "$"
        ["decimal_separator"]=>
        string(1) ","
        ["thousands_separator"]=>
        string(1) " "
        ["symbol_position"]=>
        string(1) "1"
        ["hide_decimals"]=>
        string(1) "0"
      }
      ["search_options"]=>
      array(4) {
        ["mode"]=>
        string(14) "min_max_slider"
        ["min_max_options"]=>
        array(11) {
          [0]=>
          string(2) "10"
          [1]=>
          string(2) "20"
          [2]=>
          string(2) "30"
          [3]=>
          string(2) "40"
          [4]=>
          string(2) "50"
          [5]=>
          string(3) "100"
          [6]=>
          string(3) "110"
          [7]=>
          string(3) "120"
          [8]=>
          string(3) "130"
          [9]=>
          string(3) "140"
          [10]=>
          string(3) "150"
        }
        ["slider_step_1_min"]=>
        string(1) "1"
        ["slider_step_1_max"]=>
        string(3) "150"
      }
      ["group_id"]=>
      string(1) "4"
      ["value"]=>
      string(7) "2300001"
      ["can_be_required":protected]=>
      bool(true)
      ["can_be_ordered":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "1"
      ["advanced_search_form"]=>
      string(1) "1"
    }
    [11]=>
    object(w2dc_content_field_select)#3833 (31) {
      ["selection_items"]=>
      array(16) {
        [2]=>
        string(8) "Open Air"
        [3]=>
        string(7) "Private"
        [4]=>
        string(10) "Conference"
        [1]=>
        string(9) "Gymnasium"
        [6]=>
        string(7) "Concert"
        [7]=>
        string(7) "Seminar"
        [8]=>
        string(10) "Exhibition"
        [10]=>
        string(9) "Gathering"
        [5]=>
        string(7) "Banquet"
        [9]=>
        string(8) "Festival"
        [12]=>
        string(5) "Sport"
        [13]=>
        string(8) "Training"
        [14]=>
        string(4) "Show"
        [15]=>
        string(5) "Party"
        [16]=>
        string(11) "Theme Party"
        [11]=>
        string(11) "Performance"
      }
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["can_be_searched":protected]=>
      bool(true)
      ["id"]=>
      string(2) "11"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "15"
      ["name"]=>
      string(10) "Event Type"
      ["slug"]=>
      string(10) "event_type"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(6) "select"
      ["icon_image"]=>
      string(17) "w2dc-fa-volume-up"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      array(2) {
        ["selection_items"]=>
        array(16) {
          [2]=>
          string(8) "Open Air"
          [3]=>
          string(7) "Private"
          [4]=>
          string(10) "Conference"
          [1]=>
          string(9) "Gymnasium"
          [6]=>
          string(7) "Concert"
          [7]=>
          string(7) "Seminar"
          [8]=>
          string(10) "Exhibition"
          [10]=>
          string(9) "Gathering"
          [5]=>
          string(7) "Banquet"
          [9]=>
          string(8) "Festival"
          [12]=>
          string(5) "Sport"
          [13]=>
          string(8) "Training"
          [14]=>
          string(4) "Show"
          [15]=>
          string(5) "Party"
          [16]=>
          string(11) "Theme Party"
          [11]=>
          string(11) "Performance"
        }
        ["icon_images"]=>
        array(16) {
          [2]=>
          string(0) ""
          [3]=>
          string(0) ""
          [4]=>
          string(0) ""
          [1]=>
          string(0) ""
          [6]=>
          string(22) "w2dc-fa-check-circle-o"
          [7]=>
          string(0) ""
          [8]=>
          string(0) ""
          [10]=>
          string(15) "w2dc-fa-cc-visa"
          [5]=>
          string(12) "w2dc-fa-bold"
          [9]=>
          string(0) ""
          [12]=>
          string(0) ""
          [13]=>
          string(0) ""
          [14]=>
          string(0) ""
          [15]=>
          string(0) ""
          [16]=>
          string(0) ""
          [11]=>
          string(0) ""
        }
      }
      ["search_options"]=>
      array(3) {
        ["search_input_mode"]=>
        string(11) "radiobutton"
        ["checkboxes_operator"]=>
        string(2) "OR"
        ["items_count"]=>
        int(1)
      }
      ["group_id"]=>
      string(1) "4"
      ["value"]=>
      NULL
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "1"
      ["advanced_search_form"]=>
      string(1) "1"
    }
    [13]=>
    object(w2dc_content_field_checkbox)#3832 (34) {
      ["how_display_items"]=>
      string(3) "all"
      ["columns_number"]=>
      string(1) "3"
      ["value"]=>
      array(0) {
      }
      ["icon_images"]=>
      array(8) {
        [0]=>
        string(15) "w2dc-fa-cc-amex"
        [1]=>
        string(14) "w2dc-fa-dollar"
        [2]=>
        string(16) "w2dc-fa-list-alt"
        [3]=>
        string(19) "w2dc-fa-cc-discover"
        [4]=>
        string(12) "w2dc-fa-gift"
        [5]=>
        string(12) "w2dc-fa-copy"
        [6]=>
        string(21) "w2dc-fa-cc-mastercard"
        [7]=>
        string(15) "w2dc-fa-cc-visa"
      }
      ["can_be_searched":protected]=>
      bool(true)
      ["is_search_configuration_page":protected]=>
      string(1) "1"
      ["selection_items"]=>
      array(8) {
        [0]=>
        string(16) "American Express"
        [1]=>
        string(4) "Cash"
        [2]=>
        string(6) "Cheque"
        [3]=>
        string(8) "Discover"
        [4]=>
        string(16) "Gift Sertificate"
        [5]=>
        string(8) "Interact"
        [6]=>
        string(10) "MasterCard"
        [7]=>
        string(4) "Visa"
      }
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(2) "13"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "16"
      ["name"]=>
      string(18) "Methods of Payment"
      ["slug"]=>
      string(18) "methods_of_payment"
      ["description"]=>
      string(16) "test description"
      ["type"]=>
      string(8) "checkbox"
      ["icon_image"]=>
      string(20) "w2dc-fa-check-square"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      array(4) {
        ["selection_items"]=>
        array(8) {
          [0]=>
          string(16) "American Express"
          [1]=>
          string(4) "Cash"
          [2]=>
          string(6) "Cheque"
          [3]=>
          string(8) "Discover"
          [4]=>
          string(16) "Gift Sertificate"
          [5]=>
          string(8) "Interact"
          [6]=>
          string(10) "MasterCard"
          [7]=>
          string(4) "Visa"
        }
        ["icon_images"]=>
        array(8) {
          [0]=>
          string(15) "w2dc-fa-cc-amex"
          [1]=>
          string(14) "w2dc-fa-dollar"
          [2]=>
          string(16) "w2dc-fa-list-alt"
          [3]=>
          string(19) "w2dc-fa-cc-discover"
          [4]=>
          string(12) "w2dc-fa-gift"
          [5]=>
          string(12) "w2dc-fa-copy"
          [6]=>
          string(21) "w2dc-fa-cc-mastercard"
          [7]=>
          string(15) "w2dc-fa-cc-visa"
        }
        ["how_display_items"]=>
        string(3) "all"
        ["columns_number"]=>
        string(1) "3"
      }
      ["search_options"]=>
      array(2) {
        ["search_input_mode"]=>
        string(10) "checkboxes"
        ["checkboxes_operator"]=>
        string(2) "OR"
      }
      ["group_id"]=>
      string(1) "4"
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["on_search_form"]=>
      string(1) "1"
      ["advanced_search_form"]=>
      string(1) "1"
    }
    [14]=>
    object(w2dc_content_field_website)#3831 (35) {
      ["is_blank"]=>
      int(1)
      ["is_nofollow"]=>
      int(1)
      ["use_link_text"]=>
      int(1)
      ["default_link_text"]=>
      string(13) "view our site"
      ["use_default_link_text"]=>
      int(0)
      ["value"]=>
      array(2) {
        ["url"]=>
        string(29) "https://www.salephpscripts.com"
        ["text"]=>
        string(9) "link text"
      }
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_configuration_page":protected]=>
      string(1) "1"
      ["id"]=>
      string(2) "14"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "17"
      ["name"]=>
      string(7) "Website"
      ["slug"]=>
      string(7) "website"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(7) "website"
      ["icon_image"]=>
      string(13) "w2dc-fa-globe"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "1"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      array(5) {
        ["is_blank"]=>
        int(1)
        ["is_nofollow"]=>
        int(1)
        ["use_link_text"]=>
        int(1)
        ["default_link_text"]=>
        string(13) "view our site"
        ["use_default_link_text"]=>
        int(0)
      }
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "2"
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [15]=>
    object(w2dc_content_field_email)#3830 (30) {
      ["can_be_ordered":protected]=>
      bool(false)
      ["id"]=>
      string(2) "15"
      ["is_core_field"]=>
      string(1) "0"
      ["order_num"]=>
      string(2) "18"
      ["name"]=>
      string(5) "Email"
      ["slug"]=>
      string(5) "email"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(5) "email"
      ["icon_image"]=>
      string(18) "w2dc-fa-envelope-o"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "2"
      ["value"]=>
      string(15) "admin@admin.com"
      ["can_be_required":protected]=>
      bool(true)
      ["is_categories":protected]=>
      bool(true)
      ["is_slug":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [6]=>
    object(w2dc_content_field_tags)#3829 (30) {
      ["can_be_required":protected]=>
      bool(false)
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_categories":protected]=>
      bool(false)
      ["is_slug":protected]=>
      bool(false)
      ["id"]=>
      string(1) "6"
      ["is_core_field"]=>
      string(1) "1"
      ["order_num"]=>
      string(2) "19"
      ["name"]=>
      string(12) "Listing Tags"
      ["slug"]=>
      string(12) "listing_tags"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(4) "tags"
      ["icon_image"]=>
      string(12) "w2dc-fa-tags"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "0"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "0"
      ["on_listing_page"]=>
      string(1) "1"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(2) {
        [0]=>
        string(1) "1"
        [1]=>
        string(1) "2"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["value"]=>
      NULL
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
    [2]=>
    object(w2dc_content_field_excerpt)#3828 (30) {
      ["can_be_ordered":protected]=>
      bool(false)
      ["is_categories":protected]=>
      bool(false)
      ["is_slug":protected]=>
      bool(false)
      ["id"]=>
      string(1) "2"
      ["is_core_field"]=>
      string(1) "1"
      ["order_num"]=>
      string(2) "20"
      ["name"]=>
      string(7) "Summary"
      ["slug"]=>
      string(7) "summary"
      ["description"]=>
      string(0) ""
      ["type"]=>
      string(7) "excerpt"
      ["icon_image"]=>
      string(20) "w2dc-fa-hand-o-right"
      ["is_required"]=>
      string(1) "0"
      ["is_ordered"]=>
      string(1) "0"
      ["is_hide_name"]=>
      string(1) "1"
      ["for_admin_only"]=>
      string(1) "0"
      ["on_exerpt_page"]=>
      string(1) "1"
      ["on_listing_page"]=>
      string(1) "0"
      ["on_map"]=>
      string(1) "0"
      ["categories"]=>
      array(0) {
      }
      ["levels"]=>
      array(4) {
        [0]=>
        string(1) "4"
        [1]=>
        string(1) "1"
        [2]=>
        string(1) "2"
        [3]=>
        string(1) "3"
      }
      ["options"]=>
      string(0) ""
      ["search_options"]=>
      string(0) ""
      ["group_id"]=>
      string(1) "0"
      ["value"]=>
      NULL
      ["can_be_required":protected]=>
      bool(true)
      ["is_configuration_page":protected]=>
      string(1) "0"
      ["can_be_searched":protected]=>
      bool(false)
      ["is_search_configuration_page":protected]=>
      string(1) "0"
      ["on_search_form"]=>
      string(1) "0"
      ["advanced_search_form"]=>
      string(1) "0"
    }
  }
  ["map_zoom"]=>
  string(2) "11"
  ["logo_image"]=>
  int(3542)
  ["images"]=>
  array(2) {
    [3542]=>
    array(29) {
      ["ID"]=>
      int(3542)
      ["post_author"]=>
      string(1) "1"
      ["post_date"]=>
      string(19) "2014-11-13 14:22:35"
      ["post_date_gmt"]=>
      string(19) "2014-11-13 14:22:35"
      ["post_content"]=>
      string(0) ""
      ["post_title"]=>
      string(0) ""
      ["post_excerpt"]=>
      string(0) ""
      ["post_status"]=>
      string(7) "inherit"
      ["comment_status"]=>
      string(4) "open"
      ["ping_status"]=>
      string(4) "open"
      ["post_password"]=>
      string(0) ""
      ["post_name"]=>
      string(8) "dscn0618"
      ["to_ping"]=>
      string(0) ""
      ["pinged"]=>
      string(0) ""
      ["post_modified"]=>
      string(19) "2020-02-27 19:23:32"
      ["post_modified_gmt"]=>
      string(19) "2020-02-27 13:23:32"
      ["post_content_filtered"]=>
      string(0) ""
      ["post_parent"]=>
      int(0)
      ["guid"]=>
      string(49) "http://wp/wp-content/uploads/2014/11/DSCN0618.jpg"
      ["menu_order"]=>
      int(0)
      ["post_type"]=>
      string(10) "attachment"
      ["post_mime_type"]=>
      string(10) "image/jpeg"
      ["comment_count"]=>
      string(1) "0"
      ["filter"]=>
      string(3) "raw"
      ["robotsmeta"]=>
      NULL
      ["ancestors"]=>
      array(0) {
      }
      ["page_template"]=>
      string(0) ""
      ["post_category"]=>
      array(0) {
      }
      ["tags_input"]=>
      array(0) {
      }
    }
    [19077]=>
    array(29) {
      ["ID"]=>
      int(19077)
      ["post_author"]=>
      string(1) "1"
      ["post_date"]=>
      string(19) "2019-10-23 00:05:54"
      ["post_date_gmt"]=>
      string(19) "2019-10-22 18:05:54"
      ["post_content"]=>
      string(0) ""
      ["post_title"]=>
      string(0) ""
      ["post_excerpt"]=>
      string(0) ""
      ["post_status"]=>
      string(7) "inherit"
      ["comment_status"]=>
      string(4) "open"
      ["ping_status"]=>
      string(6) "closed"
      ["post_password"]=>
      string(0) ""
      ["post_name"]=>
      string(5) "19077"
      ["to_ping"]=>
      string(0) ""
      ["pinged"]=>
      string(0) ""
      ["post_modified"]=>
      string(19) "2020-02-27 19:23:32"
      ["post_modified_gmt"]=>
      string(19) "2020-02-27 13:23:32"
      ["post_content_filtered"]=>
      string(0) ""
      ["post_parent"]=>
      int(7038)
      ["guid"]=>
      string(72) "http://wp/directory-classifieds-ru/barkan-neal-j-esq-2/attachment/19077/"
      ["menu_order"]=>
      int(0)
      ["post_type"]=>
      string(10) "attachment"
      ["post_mime_type"]=>
      string(10) "image/jpeg"
      ["comment_count"]=>
      string(1) "0"
      ["filter"]=>
      string(3) "raw"
      ["robotsmeta"]=>
      NULL
      ["ancestors"]=>
      array(1) {
        [0]=>
        int(7038)
      }
      ["page_template"]=>
      string(0) ""
      ["post_category"]=>
      array(0) {
      }
      ["tags_input"]=>
      array(0) {
      }
    }
  }
  ["videos"]=>
  array(0) {
  }
  ["map"]=>
  NULL
  ["is_claimable"]=>
  string(1) "1"
  ["claim"]=>
  object(w2dc_listing_claim)#3825 (5) {
    ["listing_id"]=>
    int(70)
    ["claimer_id"]=>
    NULL
    ["claimer"]=>
    NULL
    ["claimer_message"]=>
    NULL
    ["status"]=>
    NULL
  }
  ["logo_animation_effect"]=>
  NULL
  ["contact_email"]=>
  string(0) ""
}

 */

<?php 

class w2dc_listings_manager {
	public $current_listing;
	
	public function __construct() {
		global $pagenow;

		add_action('add_meta_boxes', array($this, 'addListingInfoMetabox'));
		add_action('add_meta_boxes', array($this, 'addExpirationDateMetabox'));
		add_action('add_meta_boxes', array($this, 'addOrderDateMetabox'));
		if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			add_action('add_meta_boxes', array($this, 'addClaimingMetabox'));
		}

		if (get_option('w2dc_listing_contact_form') && get_option('w2dc_custom_contact_email')) {
			add_action('add_meta_boxes', array($this, 'addContactEmailMetabox'));
		}
		
		add_action('add_meta_boxes', array($this, 'addMediaMetabox'));
		
		add_filter('postbox_classes_' . W2DC_POST_TYPE . '_w2dc_listing_info', array($this, 'addMetaboxClasses'));

		add_action('admin_init', array($this, 'setCurrentDirectory'), 1);

		add_action('admin_init', array($this, 'loadCurrentListing'));

		add_action('admin_init', array($this, 'initHooks'));
		
		add_filter('manage_'.W2DC_POST_TYPE.'_posts_columns', array($this, 'add_listings_table_columns'));
		add_filter('manage_'.W2DC_POST_TYPE.'_posts_custom_column', array($this, 'manage_listings_table_rows'), 10, 2);
		add_filter('post_row_actions', array($this, 'add_row_actions'), 10, 2);
		
		add_action('restrict_manage_posts', array($this, 'posts_filter_dropdown'));
		add_filter('request', array( $this, 'posts_filter'));
		
		add_action('admin_menu', array($this, 'addRaiseUpPage'));
		add_action('admin_menu', array($this, 'addRenewPage'));
		add_action('admin_menu', array($this, 'addChangeDatePage'));
		add_action('admin_menu', array($this, 'addUpgradePage'));
		add_action('admin_menu', array($this, 'addBulkUpgradePage'));
		add_action('admin_menu', array($this, 'addProcessClaimPage'));
		
		add_action('admin_footer-edit.php', array($this, 'upgradeListingBulkAction'));
		add_action('load-edit.php', array($this, 'upgradeListingBulkActionHandle'));

		if ((isset($_POST['publish']) || isset($_POST['save']) || w2dc_getValue($_POST, 'action') == 'editpost' || isset($_POST['w2dc_save_as_active'])) && (isset($_POST['post_type']) && $_POST['post_type'] == W2DC_POST_TYPE)) {
			add_filter('wp_insert_post_empty_content', array($this, 'saveDirectoryMeta'), 99, 2);
			// the post with empty title will not call this filter!
			add_filter('wp_insert_post_data', array($this, 'validateListing'), 99, 2);

			// adapted for WPML
			//if (!isset($_POST['icl_trid'])) {
				add_filter('redirect_post_location', array($this, 'redirectAfterSave'));
				
				add_action('save_post_' . W2DC_POST_TYPE, array($this, 'saveListing'), 10, 3);
			//}
		}
		
		// update terms counts
		add_action('transition_post_status', array($this, 'post_status_change'), 10, 3);

		// adapted for WPML
		add_action('icl_make_duplicate', array($this, 'handle_wpml_make_duplicate'), 10, 4);
		//add_action('w2dc_listing_creation', array($this, 'wpml_copy_translations'));
		//add_action('w2dc_listing_creation_front', array($this, 'wpml_copy_translations'));
		
		add_action('post_updated', array($this, 'avoid_redirection_plugin'), 10, 1);
		
		add_filter('w2dc_count_attachments', array($this, 'count_attachments'), 10, 2);
		
		// disable comments at the page template, render reviews only in listing tab
		add_filter('comments_open', array($this, 'disable_comments_on_listing_page_template'), 1000, 2);
		add_filter('get_comments_number', array($this, 'disable_comments_on_listing_page_template'), 1000, 2);
	}
	
	public function post_status_change($new_status, $old_status, $post) {
		if (
			$post->post_type == W2DC_POST_TYPE &&
			($listing = w2dc_getListing($post))
		) {
			w2dc_updateTermCountByPost($post);
		}
	}
	
	public function count_attachments($do_upload, $post_id) {
		if ($listing = w2dc_getListing($post_id)) {
			$existed_images_count = count($listing->images);
			
			if ($existed_images_count >= $listing->level->images_number) {
				$do_upload = false;
			}
		}
		
		return $do_upload;
	}
	
	public function addMetaboxClasses($classes = array()) {
		$classes[] = 'w2dc-sidebar-metabox';
	
		return $classes;
	}
	
	public function addListingInfoMetabox($post_type) {
		if ($post_type == W2DC_POST_TYPE) {
			add_meta_box('w2dc_listing_info',
					__('Listing Info', 'W2DC'),
					array($this, 'listingInfoMetabox'),
					W2DC_POST_TYPE,
					'side',
					'high');
		}
	}

	public function addExpirationDateMetabox($post_type) {
		$listing = w2dc_getCurrentListingInAdmin();
		if ($post_type == W2DC_POST_TYPE && !$this->current_listing->level->eternal_active_period && (get_option('w2dc_change_expiration_date') || current_user_can('manage_options'))) {
			add_meta_box('w2dc_listing_expiration_date',
					__('Listing expiration date', 'W2DC'),
					array($this, 'listingExpirationDateMetabox'),
					W2DC_POST_TYPE,
					'normal',
					'high');
		}
	}
	
	public function addOrderDateMetabox($post_type) {
		$listing = w2dc_getCurrentListingInAdmin();
		if ($post_type == W2DC_POST_TYPE && current_user_can('manage_options')) {
			add_meta_box('w2dc_listing_order_date',
					__('Listing sorting date', 'W2DC'),
					array($this, 'listingOrderDateMetabox'),
					W2DC_POST_TYPE,
					'normal',
					'high');
		}
	}

	public function addClaimingMetabox($post_type) {
		if ($post_type == W2DC_POST_TYPE) {
			add_meta_box('w2dc_listing_claim',
					__('Listing claim', 'W2DC'),
					array($this, 'listingClaimMetabox'),
					W2DC_POST_TYPE,
					'normal',
					'high');
		}
	}

	public function addContactEmailMetabox($post_type) {
		if ($post_type == W2DC_POST_TYPE) {
			add_meta_box('w2dc_contact_email',
					__('Contact email', 'W2DC'),
					array($this, 'listingContactEmailMetabox'),
					W2DC_POST_TYPE,
					'normal',
					'high');
		}
	}
	
	public function addMediaMetabox($post_type) {
		global $w2dc_instance;
		
		if ($post_type == W2DC_POST_TYPE && ($listing = w2dc_getCurrentListingInAdmin())) {
			if ($listing->level->images_number > 0 || $listing->level->videos_number > 0) {
				$w2dc_instance->media_manager->load_media(array(
						'images' => $listing->images,
						'videos' => $listing->videos,
						'logo_image' => $listing->logo_image,
				));
				$w2dc_instance->media_manager->load_params(array(
						'object_id' => $listing->post->ID,
						'images_number' => $listing->level->images_number,
						'videos_number' => $listing->level->videos_number,
						'logo_enabled' => $listing->level->logo_enabled,
				));
				
				// add lightbox js, use only 'admin_enqueue_scripts' hook
				add_action('admin_enqueue_scripts', array($w2dc_instance->media_manager, 'admin_enqueue_scripts_styles'));
			
				add_meta_box('w2dc_media_metabox',
				__('Listing media', 'W2DC'),
				array($w2dc_instance->media_manager, 'mediaMetabox'),
				W2DC_POST_TYPE,
				'normal',
				'high',
				array('target' => 'listings'));
			}
		}
	}
	
	public function listingInfoMetabox($post) {
		global $w2dc_instance;

		$listing = w2dc_getCurrentListingInAdmin();
		$levels = $w2dc_instance->levels;
		w2dc_renderTemplate('listings/info_metabox.tpl.php', array('listing' => $listing, 'levels' => $levels));
	}
	
	public function listingExpirationDateMetabox($post) {
		global $w2dc_instance;

		$listing = w2dc_getCurrentListingInAdmin();
		if ($listing->status != 'expired') {
			// If new listing
			if (!$listing->expiration_date) {
				$listing->expiration_date = w2dc_calcExpirationDate(current_time('timestamp'), $listing->level);
			}
			w2dc_renderTemplate('listings/expiration_date_metabox.tpl.php', array('listing' => $listing, 'dateformat' => w2dc_getDatePickerFormat()));
		} else {
			echo "<p>".__('Renew listing first!', 'W2DC')."</p>";
			$renew_link = strip_tags(apply_filters('w2dc_renew_option', __('renew listing', 'W2DC'), $listing));
			if (get_option('w2dc_fsubmit_addon') && isset($w2dc_instance->dashboard_page_url) && $w2dc_instance->dashboard_page_url)
				echo '<br /><a href="' . w2dc_dashboardUrl(array('w2dc_action' => 'renew_listing', 'listing_id' => $listing->post->ID)) . '"><span class="w2dc-fa w2dc-fa-refresh w2dc-fa-lg"></span> ' . $renew_link . '</a>';
			else
				echo '<br /><a href="' . admin_url('options.php?page=w2dc_renew&listing_id=' . $listing->post->ID) . '"><span class="w2dc-fa w2dc-fa-refresh w2dc-fa-lg"></span> ' . $renew_link . '</a>';
			do_action('w2dc_listing_status_option', $listing);
		}
	}
	
	public function listingOrderDateMetabox($post) {
		global $w2dc_instance;

		$listing = w2dc_getCurrentListingInAdmin();
		if ($listing->status != 'expired') {
			// If new listing
			if (!$listing->order_date) {
				$listing->order_date = time();
			}
			w2dc_renderTemplate('listings/order_date_metabox.tpl.php', array('listing' => $listing, 'dateformat' => w2dc_getDatePickerFormat()));
		} else {
			echo "<p>".__('Renew listing first!', 'W2DC')."</p>";
			$renew_link = strip_tags(apply_filters('w2dc_renew_option', __('renew listing', 'W2DC'), $listing));
			if (get_option('w2dc_fsubmit_addon') && isset($w2dc_instance->dashboard_page_url) && $w2dc_instance->dashboard_page_url)
				echo '<br /><a href="' . w2dc_dashboardUrl(array('w2dc_action' => 'renew_listing', 'listing_id' => $listing->post->ID)) . '"><span class="w2dc-fa w2dc-fa-refresh w2dc-fa-lg"></span> ' . $renew_link . '</a>';
			else
				echo '<br /><a href="' . admin_url('options.php?page=w2dc_renew&listing_id=' . $listing->post->ID) . '"><span class="w2dc-fa w2dc-fa-refresh w2dc-fa-lg"></span> ' . $renew_link . '</a>';
			do_action('w2dc_listing_status_option', $listing);
		}
	}

	public function listingClaimMetabox($post) {
		$listing = w2dc_getCurrentListingInAdmin();

		w2dc_renderTemplate('listings/claim_metabox.tpl.php', array('listing' => $listing));
	}

	public function listingContactEmailMetabox($post) {
		$listing = w2dc_getCurrentListingInAdmin();

		w2dc_renderTemplate('listings/contact_email_metabox.tpl.php', array('listing' => $listing));
	}
	
	public function add_listings_table_columns($columns) {
		global $w2dc_instance;

		$w2dc_columns['w2dc_level'] = __('Level', 'W2DC') . (($w2dc_instance->directories->isMultiDirectory()) ? '/' . __('Directory', 'W2DC') : '');
		$w2dc_columns['w2dc_expiration_date'] = __('Expiration date', 'W2DC');
		$w2dc_columns['w2dc_status'] = __('Status', 'W2DC');
		if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			$w2dc_columns['w2dc_claim'] = __('Claim', 'W2DC');
		}

		return array_slice($columns, 0, 2, true) + $w2dc_columns + array_slice($columns, 2, count($columns)-2, true);
	}
	
	public function manage_listings_table_rows($column, $post_id) {
		global $w2dc_instance;

		switch ($column) {
			case "w2dc_level":
				$listing = new w2dc_listing();
				$listing->loadListingFromPost($post_id);

				if ($listing->level && $listing->level->isUpgradable())
					echo '<a href="' . admin_url('options.php?page=w2dc_upgrade&listing_id=' . $post_id) . '" title="' . esc_attr__('Change level', 'W2DC') . '">';
				echo $listing->level->name;
				if ($listing->level && $listing->level->isUpgradable())
					echo ' <span class="w2dc-fa w2dc-fa-cog w2dc-fa-lg"></span></a>';

				if ($listing->level && !$listing->level->eternal_active_period)
					echo '<br />(' . $listing->level->getActivePeriodString() . ')';
				
				if ($w2dc_instance->directories->isMultiDirectory())
					echo '<br />' . $listing->directory->name;
				break;
			case "w2dc_expiration_date":
				$listing = new w2dc_listing();
				$listing->loadListingFromPost($post_id);
				if ($listing->level && $listing->level->eternal_active_period)
					_e('Eternal active period', 'W2DC');
				else {
					if ((get_option('w2dc_change_expiration_date') || current_user_can('manage_options')) && $listing->status == 'active')
						echo '<a href="' . admin_url('options.php?page=w2dc_changedate&listing_id=' . $post_id) . '" title="' . esc_attr__('change expiration date', 'W2DC') . '">' . w2dc_formatDateTime($listing->expiration_date) . '</a>';
					else
						echo w2dc_formatDateTime($listing->expiration_date);

					if ($listing->status == 'expired') {
						$renew_link = apply_filters('w2dc_renew_option', __('renew listing', 'W2DC'), $listing);
						echo '<br /><a href="' . admin_url('options.php?page=w2dc_renew&listing_id=' . $post_id) . '"><span class="w2dc-fa w2dc-fa-refresh w2dc-fa-lg"></span> ' . $renew_link . '</a>';
					} elseif ($listing->expiration_date > time()) {
						echo '<br />' . human_time_diff(time(), $listing->expiration_date) . '&nbsp;' . __('left', 'W2DC');
					}
				}
				break;
			case "w2dc_status":
				$listing = new w2dc_listing();
				$listing->loadListingFromPost($post_id);
				if ($listing->status == 'active')
					echo '<span class="w2dc-badge w2dc-listing-status-active">' . __('active', 'W2DC') . '</span>';
				elseif ($listing->status == 'expired')
					echo '<span class="w2dc-badge w2dc-listing-status-expired">' . __('expired', 'W2DC') . '</span>';
				elseif ($listing->status == 'unpaid')
					echo '<span class="w2dc-badge w2dc-listing-status-unpaid">' . __('unpaid', 'W2DC') . '</span>';
				elseif ($listing->status == 'stopped')
					echo '<span class="w2dc-badge w2dc-listing-status-stopped">' . __('stopped', 'W2DC') . '</span>';
				do_action('w2dc_listing_status_option', $listing);
				break;
			case "w2dc_claim":
				if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
					$listing = new w2dc_listing();
					$listing->loadListingFromPost($post_id);
	
					if ($listing->claim->isClaimed())
						echo $listing->claim->getClaimMessage();
					elseif ($listing->is_claimable)
						_e('Claimable', 'W2DC');
				}
				break;
		}
	}
	
	public function add_row_actions($actions, $post) {
		if ($post->post_type == W2DC_POST_TYPE){
			$listing = new w2dc_listing();
			$listing->loadListingFromPost($post);
			
			if ($listing->level->raiseup_enabled && $listing->status == 'active' && $listing->post->post_status == 'publish' && w2dc_current_user_can_edit_listing($listing->post->ID)) {
				$raise_up_link = apply_filters('w2dc_raiseup_option', __('raise up listing', 'W2DC'), $listing);
				$actions['raise_up'] = '<a href="' . admin_url('options.php?page=w2dc_raise_up&listing_id=' . $post->ID) . '"><span class="w2dc-fa w2dc-fa-level-up w2dc-fa-lg"></span> ' . $raise_up_link . '</a>';
			}
			
		}
		return $actions;
	}
	
	public function posts_filter_dropdown() {
		global $pagenow, $w2dc_instance;
		if ($pagenow === 'upload.php' || empty($_GET['post_type']) || (isset($_GET['post_type']) && $_GET['post_type'] != W2DC_POST_TYPE))
			return;

		echo '<select name="w2dc_post_status_filter">';
		echo '<option value="">' . __('Any post status', 'W2DC') . '</option>';
		echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_post_status_filter'), 'publish', false ) . 'value="publish">' . __('Published', 'W2DC') . '</option>';
		echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_post_status_filter'), 'pending', false ) . 'value="pending">' . __('Pending', 'W2DC') . '</option>';
		echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_post_status_filter'), 'draft', false ) . 'value="draft">' . __('Draft', 'W2DC') . '</option>';
		echo '</select>';

		echo '<select name="w2dc_listing_status_filter">';
		echo '<option value="">' . __('Any listing status', 'W2DC') . '</option>';
		echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_listing_status_filter'), 'active', false ) . 'value="active">' . __('Active', 'W2DC') . '</option>';
		echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_listing_status_filter'), 'expired', false ) . 'value="expired">' . __('Expired', 'W2DC') . '</option>';
		echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_listing_status_filter'), 'unpaid', false ) . 'value="unpaid">' . __('Unpaid', 'W2DC') . '</option>';
		echo '</select>';

		if ($w2dc_instance->directories->isMultiDirectory()) {
			echo '<select name="w2dc_directory_filter">';
			echo '<option value="">' . __('All directories', 'W2DC') . '</option>';
			foreach ($w2dc_instance->directories->directories_array AS $directory)
				echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_directory_filter'), $directory->id, false ) . 'value="' . $directory->id . '">' . $directory->name . '</option>';
			echo '</select>';
		}

		echo '<select name="w2dc_level_filter">';
		echo '<option value="">' . __('All listings levels', 'W2DC') . '</option>';
		foreach ($w2dc_instance->levels->levels_array AS $level)
			echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_level_filter'), $level->id, false ) . 'value="' . $level->id . '">' . $level->name . '</option>';
		echo '</select>';

		if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			echo '<select name="w2dc_claim_filter">';
			echo '<option value="">' . __('Any listings claim', 'W2DC') . '</option>';
			echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_claim_filter'), 'claimable', false ) . 'value="claimable">' . __('Only claimable', 'W2DC') . '</option>';
			echo '<option ' . selected(w2dc_getValue($_GET, 'w2dc_claim_filter'), 'claimed', false ) . 'value="claimed">' . __('Awaiting approval', 'W2DC') . '</option>';
			echo '</select>';
		}
	}
	
	public function posts_filter($vars) {
		if (isset($_GET['w2dc_post_status_filter']) && $_GET['w2dc_post_status_filter']) {
			$vars = array_merge(
				$vars,
				array(
						'post_status' => $_GET['w2dc_post_status_filter']
				)
			);
		}
		if (isset($_GET['w2dc_listing_status_filter']) && $_GET['w2dc_listing_status_filter']) {
			$vars = array_merge(
				$vars,
				array(
						'meta_query' => array(
								'relation' => 'AND',
								array(
										'key'     => '_listing_status',
										'value'   => $_GET['w2dc_listing_status_filter'],
								)
						)
				)
			);
		}
		if (isset($_GET['w2dc_directory_filter']) && $_GET['w2dc_directory_filter']) {
			$vars = w2dc_set_directory_args($vars, array($_GET['w2dc_directory_filter']));
		}
		if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter']) {
			add_filter('posts_join', array($this, 'level_filter_join'));
			add_filter('posts_where', array($this, 'level_filter_where'));
		}
		if (isset($_GET['w2dc_claim_filter']) && $_GET['w2dc_claim_filter'] && get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			if ($_GET['w2dc_claim_filter'] == 'claimable') {
				$vars = array_merge(
						$vars,
						array(
								'meta_query' => array(
										'relation' => 'AND',
										array(
												'key'     => '_is_claimable',
												'value'   => 1,
												'type'    => 'numeric',
										)
								)
						)
				);
			} elseif ($_GET['w2dc_claim_filter'] == 'claimed') {
				$vars = array_merge(
						$vars,
						array(
								'meta_query' => array(
										'relation' => 'AND',
										array(
												'key'     => '_claimer_id',
												'compare' => 'EXISTS',
										)
								)
						)
				);
				$vars = array_merge(
						$vars,
						array(
								'meta_query' => array(
										'relation' => 'AND',
										array(
												'key'     => '_claim_data',
												'value'   => 'approved',
												'compare' => 'NOT LIKE',
										)
								)
						)
				);
			}
		}
		return $vars;
	}
	
	function level_filter_join($join = '') {
		global $wpdb;

		if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter'])
			$join .= " LEFT JOIN {$wpdb->w2dc_levels_relationships} AS w2dc_lr ON w2dc_lr.post_id = {$wpdb->posts}.ID ";
	
		return $join;
	}
	
	public function level_filter_where($where = '') {
		if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter'])
			$where .= " AND (w2dc_lr.level_id=" . $_GET['w2dc_level_filter'] . ")";
		
		return $where;
	}

	public function addRaiseUpPage() {
		add_submenu_page('options.php',
				__('Raise up listing', 'W2DC'),
				__('Raise up listing', 'W2DC'),
				'publish_posts',
				'w2dc_raise_up',
				array($this, 'raiseUpListing')
		);
	}
	
	public function raiseUpListing() {
		if (isset($_GET['listing_id']) && ($listing_id = $_GET['listing_id']) && is_numeric($listing_id) && w2dc_current_user_can_edit_listing($listing_id)) {
			if ($this->loadCurrentListing($listing_id) && $this->current_listing->status == 'active') {
				$action = 'show';
				$referer = wp_get_referer();
				if (isset($_GET['raiseup_action']) && $_GET['raiseup_action'] == 'raiseup') {
					if ($this->current_listing->processRaiseUp())
						w2dc_addMessage(__('Listing was raised up successfully!', 'W2DC'));
					/* else
						w2dc_addMessage(__('An error has occurred and listing was not raised up', 'W2DC'), 'error'); */
					$action = $_GET['raiseup_action'];
					$referer = $_GET['referer'];
				}
				w2dc_renderTemplate('listings/raise_up.tpl.php', array('listing' => $this->current_listing, 'referer' => $referer, 'action' => $action));
			} else
				exit();
		} else
			exit();
	}

	public function addRenewPage() {
		add_submenu_page('options.php',
				__('Renew listing', 'W2DC'),
				__('Renew listing', 'W2DC'),
				'publish_posts',
				'w2dc_renew',
				array($this, 'renewListing')
		);
	}
	
	public function renewListing() {
		if (isset($_GET['listing_id']) && ($listing_id = $_GET['listing_id']) && is_numeric($listing_id) && w2dc_current_user_can_edit_listing($listing_id)) {
			if ($this->loadCurrentListing($listing_id)) {
				$action = 'show';
				$referer = wp_get_referer();
				if (isset($_GET['renew_action']) && $_GET['renew_action'] == 'renew') {
					if ($this->current_listing->processActivate(true, false)) {
						w2dc_addMessage(__('Listing was renewed successfully!', 'W2DC'));
					}
					/* else
						w2dc_addMessage(__('An error has occurred and listing was not renewed', 'W2DC'), 'error'); */
					$action = $_GET['renew_action'];
					$referer = $_GET['referer'];
				}
				w2dc_renderTemplate('listings/renew.tpl.php', array('listing' => $this->current_listing, 'referer' => $referer, 'action' => $action));
			} else
				exit();
		} else
			exit();
	}
	
	public function addChangeDatePage() {
		if (get_option('w2dc_change_expiration_date') || current_user_can('manage_options'))
			add_submenu_page('options.php',
					__('Change expiration date', 'W2DC'),
					__('Change expiration date', 'W2DC'),
					'publish_posts',
					'w2dc_changedate',
					array($this, 'changeDateListingPage')
			);
	}
	
	public function changeDateListingPage() {
		if (isset($_GET['listing_id']) && ($listing_id = $_GET['listing_id']) && is_numeric($listing_id) && w2dc_current_user_can_edit_listing($listing_id)) {
			if ($this->loadCurrentListing($listing_id)) {
				$action = 'show';
				$referer = wp_get_referer();
				if (isset($_GET['changedate_action']) && $_GET['changedate_action'] == 'changedate') {
					$this->changeExpirationDate();
					$action = $_GET['changedate_action'];
					$referer = $_GET['referer'];
				}

				w2dc_renderTemplate('listings/expiration_date.tpl.php', array('listing' => $this->current_listing, 'referer' => $referer, 'action' => $action, 'dateformat' => w2dc_getDatePickerFormat()));
			} else
				exit();
		} else
			exit();
	}
	
	public function changeExpirationDate() {
		$w2dc_form_validation = new w2dc_form_validation();
		$w2dc_form_validation->set_rules('expiration_date_tmstmp', __('Expiration date', 'W2DC'), 'required|integer');
		$w2dc_form_validation->set_rules('expiration_date_hour', __('Expiration hour', 'W2DC'), 'required|integer');
		$w2dc_form_validation->set_rules('expiration_date_minute', __('Expiration minute', 'W2DC'), 'required|integer');

		if ($w2dc_form_validation->run()) {
			// show message when expiration date was changed and listing was already created
			if ($this->current_listing->saveExpirationDate($w2dc_form_validation->result_array()) && get_post_meta($this->current_listing->post->ID, '_listing_created', true)) {
				w2dc_addMessage(__('Expiration date of listing was changed successfully!', 'W2DC'));
				$this->current_listing->loadListingFromPost($this->current_listing->post->ID);
			}
		} elseif ($error_string = $w2dc_form_validation->error_array()) {
			w2dc_addMessage($error_string, 'error');
		}
	}
	
	public function changeOrderDate() {
		$w2dc_form_validation = new w2dc_form_validation();
		$w2dc_form_validation->set_rules('order_date_tmstmp', __('Sorting date', 'W2DC'), 'required|integer');
		$w2dc_form_validation->set_rules('order_date_hour', __('Sorting hour', 'W2DC'), 'required|integer');
		$w2dc_form_validation->set_rules('order_date_minute', __('Sorting minute', 'W2DC'), 'required|integer');

		if ($w2dc_form_validation->run()) {
			// show message when expiration date was changed and listing was already created
			if ($this->current_listing->saveOrderDate($w2dc_form_validation->result_array()) && get_post_meta($this->current_listing->post->ID, '_listing_created', true)) {
				w2dc_addMessage(__('Sorting date of listing was changed successfully!', 'W2DC'));
				$this->current_listing->loadListingFromPost($this->current_listing->post->ID);
			}
		} elseif ($error_string = $w2dc_form_validation->error_array()) {
			w2dc_addMessage($error_string, 'error');
		}
	}
	
	public function addUpgradePage() {
		add_submenu_page('options.php',
				__('Change level of listing', 'W2DC'),
				__('Change level of listing', 'W2DC'),
				'publish_posts',
				'w2dc_upgrade',
				array($this, 'upgradeListingPage')
		);
	}
	
	public function upgradeListingPage() {
		global $w2dc_instance;
		
		if (isset($_GET['listing_id']) && ($listing_id = $_GET['listing_id']) && is_numeric($listing_id) && w2dc_current_user_can_edit_listing($listing_id)) {
			if ($this->loadCurrentListing($listing_id)) {
				$action = 'show';
				$referer = wp_get_referer();
				if (isset($_GET['upgrade_action']) && $_GET['upgrade_action'] == 'upgrade') {
					$w2dc_form_validation = new w2dc_form_validation();
					$w2dc_form_validation->set_rules('new_level_id', __('New level ID', 'W2DC'), 'required|integer');

					if ($w2dc_form_validation->run()) {
						if ($this->current_listing->changeLevel($w2dc_form_validation->result_array('new_level_id')))
							w2dc_addMessage(__('Listing level was changed successfully!', 'W2DC'));
						$action = $_GET['upgrade_action'];
					} else
						w2dc_addMessage(__('New level must be selected!', 'W2DC'), 'error');
					
					$referer = $_GET['referer'];
				}

				w2dc_renderTemplate('listings/upgrade.tpl.php', array('listing' => $this->current_listing, 'referer' => $referer, 'action' => $action, 'levels' => $w2dc_instance->levels));
			} else
				exit();
		} else
			exit();
	}
	
	public function addBulkUpgradePage() {
		add_submenu_page('options.php',
				__('Change level of listings', 'W2DC'),
				__('Change level of listings', 'W2DC'),
				'publish_posts',
				'w2dc_upgrade_bulk',
				array($this, 'upgradeListingsBulkPage')
		);
	}
	
	public function upgradeListingsBulkPage() {
		global $w2dc_instance;
	
		if (isset($_GET['listings_ids'])) {
			$listings_ids = array_map('intval', explode(',', $_GET['listings_ids']));

			$action = 'show';
			$referer = $_GET['referer'];
			if (isset($_GET['upgrade_action']) && $_GET['upgrade_action'] == 'upgrade') {
				$action = $_GET['upgrade_action'];

				$w2dc_form_validation = new w2dc_form_validation();
				$w2dc_form_validation->set_rules('new_level_id', __('New level ID', 'W2DC'), 'required|integer');
				if ($w2dc_form_validation->run()) {
					$new_level_id = $w2dc_form_validation->result_array('new_level_id');
					$upgraded = 0;
					foreach ($listings_ids AS $listing_id) {
						if (is_numeric($listing_id) && w2dc_current_user_can_edit_listing($listing_id))
							if ($this->loadCurrentListing($listing_id)) {
								if ($this->current_listing->changeLevel($new_level_id))
									$upgraded++;
							} else
								exit();
					}
					if ($upgraded)
						w2dc_addMessage(sprintf(_n('%d listing has changed level successfully!', '%d listings have changed levels successfully!', $upgraded, 'W2DC'), $upgraded));
				} else
					exit();
			}

			w2dc_renderTemplate('listings/upgrade_bulk.tpl.php', array('listings_ids' => $listings_ids, 'referer' => $referer, 'action' => $action, 'levels' => $w2dc_instance->levels));
		} else
			exit();
	}

	public function upgradeListingBulkAction() {
		global $post_type;

		if ($post_type == W2DC_POST_TYPE) {
		?>
		<script>
			(function($) {
				"use strict";

				$(function() {
					$('<option>').val('upgrade').text('<?php echo esc_js(__('Change level', 'W2DC')); ?>').appendTo("select[name='action']");
					$('<option>').val('upgrade').text('<?php echo esc_js(__('Change level', 'W2DC')); ?>').appendTo("select[name='action2']");
				});
			})(jQuery);
		</script>
		<?php
		}
	}
	
	public function upgradeListingBulkActionHandle() {
		global $typenow;

		if ($typenow == W2DC_POST_TYPE) {
			$wp_list_table = _get_list_table('WP_Posts_List_Table');
			$action = $wp_list_table->current_action();
			
			$allowed_actions = array("upgrade");
			if (!in_array($action, $allowed_actions)) return;

			check_admin_referer('bulk-posts');
			
			if (isset($_REQUEST['post']))
				$post_ids = array_map('intval', $_REQUEST['post']);
			
			if (empty($post_ids)) return;

			switch($action) {
				case 'upgrade':

				wp_redirect(admin_url('options.php?page=w2dc_upgrade_bulk&listings_ids=' . implode(',', $post_ids) . '&referer=' . urlencode(wp_get_referer())));
				die();
				break;

				default: return;
			}
		}
	}
	
	public function addProcessClaimPage() {
		add_submenu_page('options.php',
				__('Approve or decline claim', 'W2DC'),
				__('Approve or decline claim', 'W2DC'),
				'publish_posts',
				'w2dc_process_claim',
				array($this, 'processClaim')	
		);
	}
	
	public function processClaim() {
		if (isset($_GET['listing_id']) && ($listing_id = $_GET['listing_id']) && is_numeric($listing_id) && w2dc_current_user_can_edit_listing($listing_id)) {
			if ($this->loadCurrentListing($listing_id)) {
				$action = 'show';
				$referer = wp_get_referer();
				if (isset($_GET['claim_action']) && ($_GET['claim_action'] == 'approve' || $_GET['claim_action'] == 'decline')) {
					if ($_GET['claim_action'] == 'approve') {
						$this->current_listing->claim->approve();
						if (get_option('w2dc_claim_approval_notification')) {
							$claimer = get_userdata($this->current_listing->claim->claimer_id);
	
							$subject = __('Approval of claim notification', 'W2DC');
								
							$body = str_replace('[claimer]', $claimer->display_name,
									str_replace('[listing]', $this->current_listing->post->post_title,
									str_replace('[link]', w2dc_dashboardUrl(),
							get_option('w2dc_claim_approval_notification'))));
								
							w2dc_mail($claimer->user_email, $subject, $body);
						}
						w2dc_addMessage(__('Listing claim was approved successfully!', 'W2DC'));
					} elseif ($_GET['claim_action'] == 'decline') {
						$this->current_listing->claim->deleteRecord();
						if (get_option('w2dc_claim_decline_notification')) {
							$claimer = get_userdata($this->current_listing->claim->claimer_id);

							$subject = __('Claim decline notification', 'W2DC');
								
							$body = str_replace('[claimer]', $claimer->display_name,
									str_replace('[listing]', $this->current_listing->post->post_title,
									get_option('w2dc_claim_decline_notification')));
								
							w2dc_mail($claimer->user_email, $subject, $body);
						}
						update_post_meta($this->current_listing->post->ID, '_is_claimable', true);
						w2dc_addMessage(__('Listing claim was declined!', 'W2DC'));
					}
					$action = 'processed';
					$referer = $_GET['referer'];
				}
				w2dc_renderTemplate('listings/claim_process.tpl.php', array('listing' => $this->current_listing, 'referer' => $referer, 'action' => $action));
			} else
				exit();
		} else
			exit();
	}
	
	public function loadCurrentListing($listing_id = null) {
		global $w2dc_instance, $pagenow;

		if ($pagenow == 'post-new.php' && isset($_GET['post_type']) && $_GET['post_type'] == W2DC_POST_TYPE && isset($_GET['level_id']) && is_numeric($_GET['level_id'])) {
			// New post
			$level_id = $_GET['level_id'];
			$this->current_listing = new w2dc_listing($level_id);
			$w2dc_instance->current_listing = $this->current_listing;

			if ($this->current_listing->level) {
				// need to load draft post into current_listing property
				add_action('save_post', array($this, 'saveInitialDraft'), 10);
			} else {
				wp_redirect(add_query_arg('page', 'w2dc_choose_level', admin_url('options.php')));
				die();
			}
		} elseif (
			$listing_id
			||
			($pagenow == 'post.php' && isset($_GET['post']) && ($post = get_post($_GET['post'])) && $post->post_type == W2DC_POST_TYPE)
			||
			($pagenow == 'post.php' && isset($_POST['post_ID']) && ($post = get_post($_POST['post_ID'])) && $post->post_type == W2DC_POST_TYPE)
		) {
			if (empty($post) && $listing_id) {
				$post = get_post($listing_id);
			}

			// Existed post
			$this->loadListing($post);
		}
		return $this->current_listing;
	}
	
	public function loadListing($listing_post) {
		global $w2dc_instance;

		$listing = new w2dc_listing();
		if ($listing->loadListingFromPost($listing_post)) {
			$this->current_listing = $listing;
			$w2dc_instance->current_listing = $listing;
		
			return $listing;
		}
	}
	
	public function saveInitialDraft($post_id) {
		if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE)
			return;

		global $w2dc_instance;
		$this->current_listing->loadListingFromPost($post_id);
		$w2dc_instance->current_listing = $this->current_listing;

		// $w2dc_instance::setCurrentDirectory() for the frontend or self::setCurrentDirectory() for the backend
		if ($w2dc_instance->current_directory) {
			update_post_meta($post_id, '_directory_id', $w2dc_instance->current_directory->id);
		}
		
		$this->saveLevel();
		
		return $this->current_listing->setLevelByPostId();
	}
	
	public function saveLevel() {
		global $wpdb;
	
		$wpdb->query($wpdb->prepare("INSERT INTO {$wpdb->w2dc_levels_relationships} (post_id, level_id) VALUES(%d, %d) ON DUPLICATE KEY UPDATE level_id=%d", $this->current_listing->post->ID, $this->current_listing->level->id, $this->current_listing->level->id));
	}
	
	public function saveDirectoryMeta($maybe_empty, $postarr) {
		global $w2dc_instance;

		if (
			w2dc_getValue($postarr, 'ID') &&
			w2dc_getValue($postarr, 'post_type') == W2DC_POST_TYPE &&
			isset($_POST['directory_id']) &&
			is_numeric($_POST['directory_id']) &&
			($directory = $w2dc_instance->directories->getDirectoryById($_POST['directory_id']))
		) {
			$this->loadCurrentListing($postarr['ID']);
			if ($this->current_listing->directory->id != $directory->id) {
				update_post_meta($this->current_listing->post->ID, '_directory_id', $directory->id);
				w2dc_addMessage(__("Listing directory was changed!", "W2DC"));
			}
		}
		
		return $maybe_empty;
	}

	public function validateListing($data, $postarr) {
		// this condition in order to avoid mismatch of post type for invoice - when new listing created,
		// then it redirects to create new invoice and here it calls this function because earlier we check post type by $_POST['post_type']
		if ($data['post_type'] == W2DC_POST_TYPE) {
			global $w2dc_instance;
	
			if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE)
				return;
	
			$errors = array();
			
			if (!isset($postarr['post_title']) || !$postarr['post_title'] || $postarr['post_title'] == __('Auto Draft'))
				$errors[] = __('Listing title field required', 'W2DC');

			$post_categories_ids = array();
			if ($this->current_listing->level->categories_number > 0 || $this->current_listing->level->unlimited_categories) {
				$post_categories_ids = $w2dc_instance->categories_manager->validateCategories($this->current_listing->level, $postarr, $errors);
			}

			$w2dc_instance->content_fields->saveValues($this->current_listing->post->ID, $post_categories_ids, $this->current_listing->level->id, $errors, $data);

			if ($this->current_listing->level->locations_number) {
				if ($validation_results = $w2dc_instance->locations_manager->validateLocations($this->current_listing->level, $errors)) {
					$w2dc_instance->locations_manager->saveLocations($this->current_listing->level, $this->current_listing->post->ID, $validation_results);
				}
			}
	
			if ($this->current_listing->level->images_number || $this->current_listing->level->videos_number) {
				$w2dc_instance->media_manager->load_params(array(
					'object_id' => $this->current_listing->post->ID,
					'images_number' => $this->current_listing->level->images_number,
					'videos_number' => $this->current_listing->level->videos_number,
					'logo_enabled' => $this->current_listing->level->logo_enabled,
				));
				
				if ($validation_results = $w2dc_instance->media_manager->validateAttachments($errors)) {
					$w2dc_instance->media_manager->saveAttachments($validation_results);
				}
			}

			if (get_option('w2dc_listing_contact_form') && get_option('w2dc_custom_contact_email')) {
				if (isset($_POST['contact_email'])) {
					if (is_email($_POST['contact_email']) || empty($_POST['contact_email'])) {
						update_post_meta($this->current_listing->post->ID, '_contact_email', $_POST['contact_email']);
					} else {
						$errors[] = __("Contact email is invalid", "W2DC");
					}
				}
			}
	
			// only successfully validated listings can be completed
			if ($errors) {
				//$data['post_status'] = 'draft';
	
				foreach ($errors AS $error) {
					w2dc_addMessage($error, 'error');
				}
			} else {
				w2dc_addMessage(__('Listing was saved successfully!', 'W2DC'));
			}
		}
		return $data;
	}
	
	public function setCurrentDirectory() {
		global $w2dc_instance, $pagenow;

		if (is_admin() && $pagenow == 'post-new.php' && isset($_GET['post_type']) && $_GET['post_type'] == W2DC_POST_TYPE && isset($_GET['directory_id']) && is_numeric($_GET['directory_id']) && ($directory = $w2dc_instance->directories->getDirectoryById($_GET['directory_id']))) {
			$w2dc_instance->current_directory = $directory;
		}
	}

	public function redirectAfterSave($location) {
		global $post;

		if ($post) {
			if (is_numeric($post))
				$post = get_post($post);
			if ($post->post_type == W2DC_POST_TYPE) {
				// Remove native success 'message'
				$uri = parse_url($location);
				$uri_array = wp_parse_args($uri['query']);
				if (isset($uri_array['message']))
					unset($uri_array['message']);
				$location = add_query_arg($uri_array, 'post.php');
			}
		}

		return $location;
	}
	
	public function saveListing($post_ID, $post, $update) {
		global $w2dc_instance;
		
		$this->loadCurrentListing($post_ID);
		
		// resave listing level each time we save the listing
		$this->saveLevel();

		if (isset($_POST['w2dc_save_as_active'])) {
			update_post_meta($this->current_listing->post->ID, '_listing_status', 'active');
			
			delete_post_meta($this->current_listing->post->ID, '_expiration_notification_sent');
			delete_post_meta($this->current_listing->post->ID, '_preexpiration_notification_sent');
		}

		// only successfully validated listings can be completed
		if (in_array($post->post_status, array('publish', 'draft'))) {
			if (!($listing_created = get_post_meta($this->current_listing->post->ID, '_listing_created', true))) {
				if (!$this->current_listing->level->eternal_active_period && $this->current_listing->status != 'expired') {
					if (get_option('w2dc_change_expiration_date') || current_user_can('manage_options'))
						$this->changeExpirationDate();
					else {
						$expiration_date = w2dc_calcExpirationDate(current_time('timestamp'), $this->current_listing->level);
						add_post_meta($this->current_listing->post->ID, '_expiration_date', $expiration_date);
					}
				}
				
				add_post_meta($this->current_listing->post->ID, '_listing_created', true);
				
				if (current_user_can('manage_options')) {
					$this->changeOrderDate();
				}
				
				add_post_meta($this->current_listing->post->ID, '_listing_status', 'active');

				apply_filters('w2dc_listing_creation', $this->current_listing);
			} else {
				if (!$this->current_listing->level->eternal_active_period && $this->current_listing->status != 'expired' && (get_option('w2dc_change_expiration_date') || current_user_can('manage_options'))) {
					$this->changeExpirationDate();
				}
					
				if ($this->current_listing->status == 'expired') {
					w2dc_addMessage(esc_attr__("You can't publish listing until it has expired status! Renew listing first!", 'W2DC'), 'error');
				}
				
				if (current_user_can('manage_options')) {
					$this->changeOrderDate();
				}
				
				do_action('w2dc_listing_update', $this->current_listing);
			}
			if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality'))
				if (isset($_POST['is_claimable']))
					update_post_meta($this->current_listing->post->ID, '_is_claimable', true);
				else
					update_post_meta($this->current_listing->post->ID, '_is_claimable', false);
		}
	}
	
	public function initHooks() {
		if (current_user_can('delete_posts')) {
			add_action('delete_post', array($this, 'delete_listing_data'), 10);
		}
	}
	
	public function delete_listing_data($post_id) {
		global $w2dc_instance, $wpdb;

		$wpdb->delete($wpdb->w2dc_levels_relationships, array('post_id' => $post_id));
		
		$w2dc_instance->locations_manager->deleteLocations($post_id);
		
		$ids = $wpdb->get_col("SELECT ID FROM {$wpdb->posts} WHERE post_parent = $post_id AND post_type = 'attachment'");
		$force_delete = apply_filters('w2dc_force_delete_attachment', false, $post_id);
		foreach ($ids as $id) {
			wp_delete_attachment($id, $force_delete);
		}

		/* $children = get_children(array('post_parent' => $post_id));
		if (is_array($children) && count($children) > 0)
			foreach($children as $child)
				wp_delete_post($child->ID, true); */
	}

	// adapted for WPML
	public function handle_wpml_make_duplicate($master_post_id, $lang, $post_array, $id) {
		global $wpdb;

		$listing = new w2dc_listing();
		if (get_post_type($master_post_id) == W2DC_POST_TYPE && $listing->loadListingFromPost($master_post_id)) {
			$wpdb->query($wpdb->prepare("INSERT INTO {$wpdb->w2dc_levels_relationships} (post_id, level_id) VALUES(%d, %d) ON DUPLICATE KEY UPDATE level_id=%d", $id, $listing->level->id, $listing->level->id));

			$wpdb->delete($wpdb->w2dc_locations_relationships, array('post_id' => $id));
			wp_delete_object_term_relationships($id, W2DC_LOCATIONS_TAX);
			foreach ($listing->locations AS $location) {
				$insert_values = array(
						'post_id' => $id,
						'location_id' => apply_filters('wpml_object_id', $location->selected_location, W2DC_LOCATIONS_TAX, true, $lang),
						'place_id' => $location->place_id,
						'address_line_1' => $location->address_line_1,
						'address_line_2' => $location->address_line_2,
						'zip_or_postal_index' => $location->zip_or_postal_index,
						'additional_info' => $location->additional_info,
				);
				if ($listing->level->map) {
					$insert_values['manual_coords'] = $location->manual_coords;
					$insert_values['map_coords_1'] = $location->map_coords_1;
					$insert_values['map_coords_2'] = $location->map_coords_2;
					$insert_values['map_icon_file'] = $location->map_icon_file;
				}
				$keys = array_keys($insert_values);
				array_walk($keys, 'w2dc_wrapKeys');
				array_walk($insert_values, 'w2dc_wrapValues');
				
				$wpdb->query("INSERT INTO {$wpdb->w2dc_locations_relationships} (" . implode(', ', $keys) . ") VALUES (" . implode(', ', $insert_values) . ")");
			}
		}
	}
	
	// adapted for WPML
	public function wpml_copy_translations($listing) {
		global $sitepress, $iclTranslationManagement;
		if (function_exists('wpml_object_id_filter') && $sitepress && get_option('w2dc_enable_automatic_translations') && ($languages = $sitepress->get_active_languages()) && count($languages) > 1) {
			$master_post_id = $listing->post->ID;

			remove_filter('wp_insert_post_data', array($this, 'validateListing'), 99);
			remove_filter('redirect_post_location', array($this, 'redirectAfterSave'));
			remove_action('save_post_' . W2DC_POST_TYPE, array($this, 'saveListing'));

			$post_type = get_post_type($master_post_id);
			if ($sitepress->is_translated_post_type($post_type)) {
				foreach ($languages AS $lang_code=>$lang)
					if ($lang_code != ICL_LANGUAGE_CODE) {
						$new_listing_id = $iclTranslationManagement->make_duplicate($master_post_id, $lang_code);
						$iclTranslationManagement->reset_duplicate_flag($new_listing_id);
					}
			}

			/* global $ICL_Pro_Translation;

			$master_post_id = $listing->post->ID;

			require_once( ICL_PLUGIN_PATH . '/lib/icl_api.php' );
			require_once( ICL_PLUGIN_PATH . '/lib/xml2array.php' );
			require_once( ICL_PLUGIN_PATH . '/inc/translation-management/pro-translation.class.php' );
			require_once( ICL_PLUGIN_PATH . '/inc/translation-management/translation-management.class.php' );
			
			$iclTranslationManagement = include_once W2DC_PATH . 'wpml-workaround.php';
			
			$ICL_Pro_Translation      = new ICL_Pro_Translation();
			
			$post_type = get_post_type($master_post_id);
			if ($sitepress->is_translated_post_type($post_type)) {
				$sitepress->set_setting('sync_post_taxonomies', false);
				foreach ($languages AS $lang_code=>$lang) {
					if ($lang_code != ICL_LANGUAGE_CODE)
						if ($new_listing_id = $iclTranslationManagement->make_duplicate($master_post_id, $lang_code)) {
							$iclTranslationManagement->duplicate_taxonomies($master_post_id, $lang_code);
							$iclTranslationManagement->duplicate_custom_fields($master_post_id, $lang_code);
							$iclTranslationManagement->reset_duplicate_flag($new_listing_id);
						}
				}
			} */
		}
	}

	/* There is annoying problem from one redirection plugin */
	public function avoid_redirection_plugin($post_id) {
		if (get_post_type($post_id) == W2DC_POST_TYPE && isset($_POST['redirection_slug']))
			unset($_POST['redirection_slug']);
	}
	
	public function disable_comments_on_listing_page_template($open, $post_id) {
		
		// display comments only once by w2dc_comments_system($listing) function in functions.php
		global $w2dc_comments_displayed;
		if ($w2dc_comments_displayed) {
			return false;
		}
	
		return $open;
	}
}

?>
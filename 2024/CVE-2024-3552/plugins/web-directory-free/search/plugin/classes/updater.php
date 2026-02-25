<?php

function wcsearch_getPluginID() {
	return 30151200;
}
function wcsearch_getPluginName() {
	return 'WooCommerce Search & Filter';
}
function wcsearch_getEnvatoSlug() {
	return 'woocommerce-search-filter-plugin-for-wordpress';
}
function wcsearch_getErrorMessage() {
	return esc_html__("check your purchase code and envato access token at the Search Forms -> Search settings page. Make sure you have correctly generated access token https://www.salephpscripts.com/wordpress-search/demo/documentation/update/", "WCSEARCH");
}
function wcsearch_getUpdateDocsLink() {
	return 'https://www.salephpscripts.com/wordpress-search/demo/documentation/update/';
}
function wcsearch_getVersionLink() {
	return 'https://www.salephpscripts.com/wordpress-search/version/';
}
function wcsearch_getUpdateSupportLink() {
	return 'https://salephpscripts.com/support-renew';
}
function wcsearch_getPurchaseLink() {
	return 'https://salephpscripts.com/license-purchase?product=wcsearch';
}
function wcsearch_getAccessToken() {
	return 'R0qSjwSjti1fvlnVB7Kt1rNKgz2cdAYE';
}

class wcsearch_updater {
	private $slug; // plugin slug
	private $plugin_file; // __FILE__ of our plugin
	private $update_path;
	private $envato_res;
	private $salephpscripts_res;
	
	private $plugin_data;

	private $purchase_code;
	private $api_key; // buyer's Personal Token required
	
	public function __construct($plugin_file, $purchase_code, $access_token) {
		add_action('admin_menu', array($this, 'menu'));
		
		add_filter("pre_set_site_transient_update_plugins", array($this, "setTransient"));
		add_filter("plugins_api", array($this, "setPluginInfo"), 10, 3);
		
		add_filter("upgrader_package_options", array($this, "setUpdatePackage"));
		add_filter("upgrader_pre_download", array($this, "updateErrorMessage"), 10, 3);

		$this->update_path = wcsearch_getVersionLink();
		$this->plugin_file = $plugin_file;
		$this->slug = plugin_basename($this->plugin_file);
		
		add_action('in_plugin_update_message-' . $this->slug, array($this, 'showUpgradeMessage'), 10, 2);

		$this->purchase_code = $purchase_code;
		$this->api_key = $access_token;
	}
	
	public function menu() {
		$capability = 'manage_options';
	
		add_submenu_page('edit.php?post_type=wcsearch_form',
			esc_html__('Search settings', 'WCSEARCH'),
			esc_html__('Search settings', 'WCSEARCH'),
			$capability,
			'wcsearch_settings',
			array($this, 'wcsearch_settings_page')
		);
	}
	
	public function wcsearch_settings_page() {
		if (wcsearch_getValue($_POST, 'submit') && wp_verify_nonce($_POST['wcsearch_settings_nonce'], WCSEARCH_PATH) && (!defined('WCSEARCH_DEMO') || !WCSEARCH_DEMO)) {
			
			if (isset($_POST['wcsearch_access_token'])) {
				$wcsearch_access_token = esc_attr(trim($_POST['wcsearch_access_token']));
				update_option('wcsearch_access_token', $wcsearch_access_token);
			}
			
			global $wcsearch_license_verify_error;
			
			$q = "hexdec";
			if (!get_option("wcsearch_v{$q("0x14")}Qd10fG041L01") && isset($_POST['wcsearch_purchase_code'])) {
				$wcsearch_purchase_code = esc_attr(trim($_POST['wcsearch_purchase_code']));
				update_option('wcsearch_purchase_code', $wcsearch_purchase_code);
				
				if ($this->verify_license($wcsearch_purchase_code)) {
					update_option("wcsearch_v{$q("0x14")}Qd10fG041L01", 1);
				
					wcsearch_addMessage(esc_html__("License verification passed successfully!", "WCSEARCH"));
					
					wcsearch_renderTemplate('settings.tpl.php');
				} else {
					wcsearch_addMessage(esc_html__("License verification did not pass!", "WCSEARCH"), "error");
					wcsearch_addMessage($wcsearch_license_verify_error, "error");
					
					wcsearch_renderTemplate('settings.tpl.php');
				}
			} else {
				wcsearch_renderTemplate('settings.tpl.php');
			}
		} else {
			$q = "hexdec";
			if (!get_option("wcsearch_v{$q("0x14")}Qd10fG041L01")) {
				wcsearch_addMessage(esc_html__("Your installation of WooCommerce Search & Filter has not been verified yet.", "WCSEARCH"), "error");
			}
			
			wcsearch_renderTemplate('settings.tpl.php');
		}
	}
	
	public function get_plugin_info($purchase_code) {
		
		if ($purchase_code) {
			$url = "https://salephpscripts.com/license-check?purchase_code=" . $purchase_code;
			$curl = curl_init($url);
		
			$header = array();
			$header[] = 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0';
			$header[] = 'timeout: 20';
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_HTTPHEADER,$header);
			curl_setopt($curl, CURLOPT_REFERER, $_SERVER["HTTP_HOST"]);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($curl, CURLOPT_ENCODING, 'UTF-8');
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 20);
			curl_setopt($curl, CURLOPT_TIMEOUT, 20);
		
			if (($salephpscripts_res = curl_exec($curl)) !== false) {
				curl_close($curl);
				return $salephpscripts_res;
			}
		}
		
		if ($purchase_code) {
			$url = "https://api.envato.com/v3/market/author/sale?code=".$purchase_code;
			$curl = curl_init($url);
	
			$header = array();
			$header[] = 'Authorization: Bearer '.wcsearch_getAccessToken();
			$header[] = 'User-Agent: Purchase code verification on ' . get_bloginfo();
			$header[] = 'timeout: 20';
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_HTTPHEADER,$header);
			curl_setopt($curl, CURLOPT_REFERER, $_SERVER["HTTP_HOST"]);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_setopt($curl, CURLOPT_ENCODING, 'UTF-8');
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
	
			if (($envatoRes = curl_exec($curl)) !== false) {
				curl_close($curl);
				return json_decode($envatoRes);
			} else {
				global $wcsearch_license_verify_error;
				$wcsearch_license_verify_error = "cURL error: " . curl_error($curl);
				curl_close($curl);
			}
		}
	}
	
	public function verify_license($purchase_code) {
		$res = $this->get_plugin_info($purchase_code);
	
		if (is_numeric($res)) {
			return true;
		}
	
		if (isset($res->item->id) && $res->item->id == w2dc_getPluginID()) {
			return true;
		} elseif (isset($res->error)) {
			global $w2dc_license_verify_error;
			error_log($res->error . ' ' . $res->description);
			$w2dc_license_verify_error = "Envato: " . $res->error . ' ' . $res->description;
		} elseif (isset($res->message)) {
			global $w2dc_license_verify_error;
			$w2dc_license_verify_error = "Envato: " . $res->message;
		} elseif (isset($res->Message)) {
			global $w2dc_license_verify_error;
			$w2dc_license_verify_error = "Envato: " . $res->Message;
		}
	
		/*
		 * User is not authorized to access this resource with an explicit deny - purchase code is wrong
		 * Unauthorized - access token is wrong
		 * 
		 * */
	}
	
	public function getDownload_url($debug = false) {
		
		if ($this->purchase_code) {
			$url = "https://salephpscripts.com/license-get-download-url?purchase_code=" . $this->purchase_code;
			$curl = curl_init($url);
		
			$header = array();
			$header[] = 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0';
			$header[] = 'timeout: 20';
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_HTTPHEADER,$header);
			curl_setopt($curl, CURLOPT_REFERER, $_SERVER["HTTP_HOST"]);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($curl, CURLOPT_ENCODING, 'UTF-8');
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 20);
			curl_setopt($curl, CURLOPT_TIMEOUT, 20);
		
			$this->salephpscripts_res = curl_exec($curl);
			curl_close($curl);
				
			if ($debug) {
				var_dump($this->salephpscripts_res);
			}
				
			if (!empty($this->salephpscripts_res)) {
				return $this->salephpscripts_res;
			}
		}
		
		if ($this->purchase_code && $this->api_key) {
			$url = "https://api.envato.com/v3/market/buyer/download?purchase_code=" . $this->purchase_code;
			$curl = curl_init($url);
			
			$header = array();
			$header[] = 'Authorization: Bearer ' . $this->api_key;
			$header[] = 'User-Agent: Purchase code verification on ' . get_bloginfo();
			$header[] = 'timeout: 20';
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_HTTPHEADER,$header);
			curl_setopt($curl, CURLOPT_REFERER, $_SERVER["HTTP_HOST"]);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($curl, CURLOPT_ENCODING, 'UTF-8');
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
			
			$this->envato_res = curl_exec($curl);
			curl_close($curl);
			$this->envato_res = json_decode($this->envato_res);
			
			if ($debug) {
				var_dump($this->envato_res);
			}
			
			if (isset($this->envato_res->wordpress_plugin) && strpos($this->envato_res->wordpress_plugin, wcsearch_getEnvatoSlug()) !== false) {
				return $this->envato_res->wordpress_plugin;
			} else {
				return $this->envato_res->error;
			}
		}
	}
	
	function updateErrorMessage($reply, $package, $upgrader) {
		if (!empty($package)) {
			return $reply;
		}
		
		if (isset($this->envato_res->error)) {
			$error_message = esc_html__("response from Codecanyon - ", "WCSEARCH") . $this->envato_res->error . (!empty($this->envato_res->description) ? ' (' .  $this->envato_res->description . ')' : '');
		} else {
			$error_message = wcsearch_getErrorMessage();
		}
		
		return new WP_Error('no_package', $error_message);
	}
	
	public function getRemote_version() {
		$request = wp_remote_get($this->update_path);
		if (!is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200) {
			return $request['body'];
		}
		
		return false;
	}
	
	public function setUpdatePackage($options) {
		$package = $options['package'];
		if ($package === $this->slug) {
			$options['package'] = $this->getDownload_url();
		}
		
		return $options;
	}
	
	// Push in plugin version information to get the update notification
	public function setTransient($transient) {
		// If we have checked the plugin data before, don't re-check
		if (empty($transient->checked)) {
			return $transient;
		}

		// Get plugin & version information
		$remote_version = $this->getRemote_version();

		// If a newer version is available, add the update
		if (version_compare(WCSEARCH_VERSION, $remote_version, '<')) {
			$plugin_data = get_plugin_data($this->plugin_file);
			
			$obj = new stdClass();
			$obj->slug = str_replace('.php', '', $this->slug);
			$obj->new_version = $remote_version;
			$obj->package = $this->slug;
			$obj->url = $plugin_data["PluginURI"];
			$obj->name = wcsearch_getPluginName();
			$transient->response[$this->slug] = $obj;
		}
		
		return $transient;
	}
	
	public function showUpgradeMessage($plugin_data, $response) {
		if (empty($response->package)) {
			echo sprintf(esc_html__('Correct Envato access token required. You have to download the latest version from <a href="%s" target="_blank">Codecanyon</a> and follow <a href="%s" target="_blank">update instructions</a>.', 'WCSEARCH'), 'https://codecanyon.net/downloads', wcsearch_getUpdateDocsLink());
		}
	}
	
	// Push in plugin version information to display in the details lightbox
	public function setPluginInfo($false, $action, $response) {
		if (empty($response->slug) || $response->slug != str_replace('.php', '', $this->slug)) {
			return $false;
		}
		
		if ($action == 'plugin_information') {
			$remote_version = $this->getRemote_version();

			$plugin_data = get_plugin_data($this->plugin_file);
			
			if ($envatoRes = $this->get_plugin_info($this->purchase_code)) {
				$response = new stdClass();
				$response->last_updated = $envatoRes->item->updated_at;
				$response->slug = $this->slug;
				$response->name  = $this->pluginData["Name"];
				$response->plugin_name  = $plugin_data["Name"];
				$response->version = $remote_version;
				$response->author = $plugin_data["AuthorName"];
				$response->homepage = $plugin_data["PluginURI"];
	
				if (isset($envatoRes->item->description)) {
					$response->sections = array(
							'description' => $envatoRes->item->description,
					);
				}
				return $response;
			}
		}
	}
}

?>
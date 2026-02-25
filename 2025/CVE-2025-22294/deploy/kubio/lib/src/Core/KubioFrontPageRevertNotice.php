<?php

namespace Kubio\Core;

use Kubio\Flags;


class KubioFrontPageRevertNotice
{
    protected static $instance = null;
    public static $nonceKey = 'kubioFrontPageRevertNoticeNonce';
    public static $showNoticeFlagKey = 'showKubioFrontPageRevertNotice';
    public static $frontPageRevertedKey = 'kubioFrontPageReverted';
    public static $frontPageBackupKey = 'KubioFrontPageRevertNoticeFrontPageBackup';
    public static $menuBackupKey = 'kubioFrontPageRevertNoticeMenuBackup';
	public static $templatePartsBackupKey = 'kubioFrontPageRevertNoticeTemplatePartsBackup';
	public static $frontpageIsFromStarterContent = 'kubioFrontPageRevertFrontPageIsFromStarterContent';
	public static $globalDataBackupKey = 'kubioFrontPageRevertedGlobalDataBackup';

    protected function __construct()
    {
        add_action('wp_footer', array($this, 'onPrintNoticeWithCheck'));
        add_action('wp_ajax_kubio_front_page_revert_action', array($this, 'onKeepKubioFrontPage'));
        add_action('wp_ajax_kubio_restore_front_page', array($this, 'onRestoreUserFrontPage'));
        add_action('rest_api_init', array($this, 'initRestApi'));

    }

	public function getFeatureIsEnabled() {
		return apply_filters( 'kubio/front_page_revert_notice_is_enabled', false );
	}


	public function getIsFreshSite() {
		$value = get_option( 'fresh_site' );
		return $value;
	}
    public function initRestApi() {
        $namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/get-kubio-front-page-revert-notice-editor-html',
			array(
				'methods'             => 'GET',
				'callback'            => array($this, 'getEditorNoticeHtml'),
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
    }

    public function getEditorNoticeHtml() {
        ob_start();
        echo $this->getRestoreNoticeHTML();
        echo $this->getRestoreNoticeStyle();
        $content = ob_get_clean();
        return  new \WP_REST_Response($content, 200);
    }

    public static function getShowNoticeInEditor() {
        $instance = static::getInstance();
        return $instance->getCurrentUserIsAdmin() && $instance->shouldShowRestoreNotice() && $instance->getHasFrontPageBackupData();
    }
    public function getFrontPageBackupData() {
        $encodedData = Flags::get($this->getFrontPageBackupKey());
       if (empty($encodedData)) {
        return null;
     }

        $data = json_decode($encodedData, true);
     return $data;
    }
    //check if there is some data to restore
    public function getHasFrontPageBackupData() {
        $frontPageEncodedData = Flags::get($this->getFrontPageBackupKey());
        return !empty($frontPageEncodedData);
    }


    public function getCurrentUserIsAdmin()
    {
        return is_user_logged_in() && current_user_can('manage_options');
    }

    public function getShowNoticeKey()
    {
        $template   = get_template();
        return $template . '.' . static::$showNoticeFlagKey;
    }

	public function getGlobalDataKey() {
		$template   = get_template();
		return $template . '.' . static::$globalDataBackupKey;
	}
	public function getFrontPageFromtStarterContentKey()
	{
		$template   = get_template();
		return $template . '.' . static::$frontpageIsFromStarterContent;
	}
	public function getFrontPageBackupKey()
	{
		$template   = get_template();
		return $template . '.' . static::$frontPageBackupKey;
	}

	public function getFrontPageRevertedKey() {
		$template   = get_template();
		return $template . '.' . static::$frontPageRevertedKey;
	}

	public function getMenuBackupKey()
	{
		$template   = get_template();
		return $template . '.' . static::$menuBackupKey;
	}
	public function getTemplatePartsBackupKey() {
		$template   = get_template();
		return $template . '.' . static::$templatePartsBackupKey;
	}
    public function updateShowNoticeFlag($newValue)
    {
        Flags::set($this->getShowNoticeKey(), $newValue);
    }
    public function shouldShowRestoreNotice()
    {
        return     Flags::get($this->getShowNoticeKey());
    }



    public function onKeepKubioFrontPage()
    {
        check_ajax_referer(static::$nonceKey);
		$this->cleanUpFlags();
        wp_send_json_success();
    }


    public function onRestoreUserFrontPage()
    {
        check_ajax_referer(static::$nonceKey);
        $this->updateShowNoticeFlag(false);
        $this->restoreWebsiteFrontPage();
        $this->restoreWebsiteMenu();
		$this->restoreTemplateParts();
		$this->restoreGlobalData();
		$this->updateStartSourceToKnowItReverted();

		if(get_option('show_on_front') === 'posts') {
			$this->onUpdateBlogTemplateToHaveFrontHeader();
		}
        //mark the front page as reverted. Maybe we'll need it later to revert revert it back :D
        Flags::set($this->getFrontPageRevertedKey(), true);
		$this->cleanUpFlags();
        wp_send_json_success();
    }

	public function updateStartSourceToKnowItReverted() {
		$startSource = Flags::get( 'start_source', 'other' );
		$newStartSource = $startSource . "_r";
		Flags::set( 'start_source', $newStartSource);
	}
	public function onUpdateBlogTemplateToHaveFrontHeader() {
		$stylesheet = get_stylesheet();
		$query      = new \WP_Query(
			array(
				'post_type'      => 'wp_template',
				'post_status'    => array( 'publish' ),
				'post_name__in'  => array( 'index' ),
				'posts_per_page' => 10,
				'no_found_rows'  => true,
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_tax_query
				'tax_query'      => array(
					array(
						'taxonomy' => 'wp_theme',
						'field'    => 'name',
						'terms'    => array( $stylesheet ),
					),
				),
			)
		);
		if(!$query->have_posts()) {
			return;
		}
		$posts = $query->posts;
		if(count($posts) === 0) {
			return;
		}
		$blogPost = null;
//		foreach($posts as $post) {
//			if($post->post_name === 'home') {
//				$blogPost = $post;
//			}
//		}
		if(empty($blogPost)) {
			$blogPost = $posts[0];
		}


		//update the template part from header to front header to have the front page look the same as before the plugin
		$content = $blogPost->post_content;
		$content = str_replace('"slug":"header"', '"slug":"front-header"', $content);
		wp_update_post(
			array(
				'ID'           => $blogPost->ID,
				'post_content' => $content
			)
		);
	}

	public function restoreGlobalData() {
		$globalDataBackup = Flags::get($this->getGlobalDataKey());

		if (empty($globalDataBackup)) {
			return;
		}

		$id = kubio_global_data_post_id();
		$post                      = get_post( $id );
		if(!$post) {
			return;
		}
		wp_update_post(
			array(
				'ID'           => intval( $id ),
				'post_content' => $globalDataBackup,
			)
		);


	}

	public function cleanUpFlags() {
		Flags::delete($this->getShowNoticeKey());
		Flags::delete($this->getMenuBackupKey());
		Flags::delete($this->getFrontPageFromtStarterContentKey());
		Flags::delete($this->getTemplatePartsBackupKey());
		Flags::delete($this->getFrontPageBackupKey());
		Flags::delete($this->getGlobalDataKey());
		$this->removeBlackWizardFlags();

		//this flag should remain to know if the site was reverted or not
		//Flags::delete($this->getFrontPageRevertedKey());
	}
	public function removeBlackWizardFlags() {
		if ( Flags::get( 'black_wizard_onboarding_hash' ) ) {
			Flags::delete( 'black_wizard_onboarding_hash' );
		}
		if ( Flags::get( 'auto_start_black_wizard_onboarding' ) ) {
			Flags::delete( 'auto_start_black_wizard_onboarding' );
		}
	}

	//if this is true then a theme like vertice with starter content was used. This kind of themes only show starter content
	//if no changes had be made on the site, so to revert it we must restore blog
	public function getHasStarterContentBackup() {
		return Flags::get($this->getFrontPageFromtStarterContentKey());
	}
    public function restoreWebsiteFrontPage()
    {

		//if the frontpage comes from starter content do a different logic
		if($this->getHasStarterContentBackup()) {
			$this->restoreFrontPageForStarterContent();
			return;
		}
        $data = $this->getFrontPageBackupData();
        if (empty($data)) {
            return false;
        }
		$showOnFront = $data['showOnFront'];
		//if you want the front to show blog the front page template should be deleted.


        $frontPageId = $data['frontPageId'];
        $blogPageId = $data['blogPageId'];


        update_option('show_on_front', $showOnFront);
        update_option('page_on_front', $frontPageId);
        update_option('page_for_posts', $blogPageId);
    }
	//The starter content flow only shows up if you did not make any changes so it means your frontpage was blog before
	//So we restore the blog as homepage
	public function restoreFrontPageForStarterContent() {
		update_option('show_on_front', 'posts' );
		update_option('page_on_front', '0');
		update_option('page_for_posts', '0');

	}



    public function getCurrentMenuId()
    {
        $currentSetLocations = get_nav_menu_locations();
        $menuId = null;
        $commonHeaderLocations = array(
            'header-menu',
            'header',
            'primary',
            'main',
            'menu-1',
        );

        foreach ($currentSetLocations as $locationName => $locationId) {
            if ($menuId) {
                break;
            }
            if (in_array($locationName, $commonHeaderLocations)) {
                $menuId = $locationId;
                break;
            }
        }
        return $menuId;
    }

	public function getShouldBackupData() {
		if(!$this->getFeatureIsEnabled()) {
			return false;
		}

		//for fresh sites do not run the restore notice
		if($this->getIsFreshSite()) {
			return false;
		}


		//if the activation is not with frontpage do not backup data and mark that the notice should be displayed
		$activateWithFrontpage = Activation::load()->activeWithFrontpage();
		if(!$activateWithFrontpage) {
			return false;
		}
		return true;
	}
    public function backupUserData()
    {
		if(!$this->getShouldBackupData()) {
			return;
		}
        $this->backupWebsiteFrontPage();
        $this->backupWebsiteMenu();
        $this->updateShowNoticeFlag(true);
    }

	public function backupUserUsedStarterContentFrontpage() {
		if(!$this->getShouldBackupData()) {
			return;
		}

		Flags::set($this->getFrontPageFromtStarterContentKey(), true);
	}

	//the template parts are created later that is why we need a different function
	public function backupTemplateParts() {
		if(!$this->getShouldBackupData()) {
			return;
		}
		$entities = array_keys( Importer::getAvailableTemplateParts() );

		//we only backup the header slugs.
		$header_slugs = ['header', 'front-header'];
		$saved_template_parts = [];
		foreach ( $entities as $slug ) {
			$is_current_kubio_template = apply_filters( 'kubio/template/is_importing_kubio_template', kubio_theme_has_kubio_block_support(), $slug );

			if(!$is_current_kubio_template || !in_array($slug, $header_slugs)) {
				continue;
			}


			$content = $this->getTemplatePartContentBySlug($slug);
			if(empty($content)) {
				continue;
			}
			$saved_template_parts[$slug] = $content;
		}

		if(empty($saved_template_parts)) {
			return;
		}
		$json_content = json_encode($saved_template_parts);
		Flags::set( static::getTemplatePartsBackupKey(), $json_content );
	}




	public function restoreTemplateParts() {
		$templatePartsString = Flags::get( static::getTemplatePartsBackupKey(), array() );
		if(empty($templatePartsString)) {
			return;
		}
		$templatePartsData = json_decode($templatePartsString, true);
		foreach ( $templatePartsData as $slug => $templatePartContent) {

			$is_current_kubio_template = true;
			Importer::createTemplatePart( $slug,  $templatePartContent, true, $is_current_kubio_template ? 'kubio' : 'theme' );
		}

	}
    public function restoreWebsiteMenu()
    {
        $frontPageEncodedData = Flags::get($this->getFrontPageBackupKey());
        $menuEncodedData = Flags::get($this->getMenuBackupKey());

        $menuId =  $this->getCurrentMenuId();
        if (!$menuId) {
            return;
        }


        if (empty($frontPageEncodedData)) {
            return false;
        }

        $frontPageData = json_decode($frontPageEncodedData, true);
        $menuData = json_decode($menuEncodedData, true);
        $showOnFront = $frontPageData['showOnFront'];

        $frontPageId = $frontPageData['frontPageId'];
        $blogPageId = $frontPageData['blogPageId'];

		//if the user comes from starter content it means the theme made some changes and we can assume the site had no
		//changes so we restore to the blog
		if($this->getHasStarterContentBackup()) {
			$showOnFront = 'posts';
			$frontPageId = '0';
			$blogPageId = '0';
			$menuEncodedData = null;
		}

		$pageOnFront = $showOnFront === 'page';
		$blogOnFront = !$pageOnFront;


        //if on plugin activation there was no menu then create a fallback menu
        if (empty($menuEncodedData)) {
            $this->createFallbackMenu($menuId, $blogOnFront, $frontPageId, $blogPageId);
            return;
        }


        $menuItems     = wp_get_nav_menu_items($menuId);
        if (!$menuItems) {
            return;
        }
        $this->emptyMenuItems($menuId);
		$newMenuIdByOldMenuId = [];
        foreach ($menuData as $item) {
            $isHome = intval($item['object_id']) === intval($frontPageId);
            $isBlog = intval($item['object_id']) === intval($blogPageId);
			$parentId = $item['parent'];

			//update the parent id with the new ids
			if(!empty($parentId)) {
				$parentId = LodashBasic::get($newMenuIdByOldMenuId, $parentId, '0' );
			}
            if ($blogOnFront && $isBlog) {
                continue;
            }
            if ($blogOnFront) {
                if ($isBlog) {
                    continue;
                }
                if ($isHome) {
                   $newId =  wp_update_nav_menu_item($menuId, 0, [
                        'menu-item-title'     => __('Home', 'kubio'),
                        'menu-item-object'    => 'custom',
                        'menu-item-url'       => home_url(),
                        'menu-item-status'    => 'publish',
                        'menu-item-parent-id' => $parentId,
                        'menu-item-position'  => $item['menu_order'],
                    ]);
					$newMenuIdByOldMenuId[$item['id']] = $newId;
                    continue;
                }
            }

            $newId = wp_update_nav_menu_item($menuId, 0, [
                'menu-item-title'     => $item['title'],
                'menu-item-url'       => $item['url'],
                'menu-item-status'    => 'publish',
                'menu-item-parent-id' => $parentId,
                'menu-item-position'  => $item['menu_order'],
                'menu-item-type'      => $item['type'],
                'menu-item-object-id' => $item['object_id'],
                'menu-item-object'    => $item['object'],
            ]);

			$newMenuIdByOldMenuId[$item['id']] = $newId;
        }
    }


    public function emptyMenuItems($menuId)
    {
        if (!$menuId) {
            return;
        }
        $menuItems     = wp_get_nav_menu_items($menuId);
        if (!$menuItems) {
            return;
        }
        foreach ($menuItems as $item) {
            wp_delete_post($item->ID, true);
        }
    }

    //if there was no menu before
    public function createFallbackMenu($menuId, $blogOnFront, $frontPageId, $blogPageId)
    {

        $this->emptyMenuItems($menuId);
        if ($blogOnFront) {
            wp_update_nav_menu_item($menuId, 0, [
                'menu-item-title'     => __('Home', 'kubio'),
                'menu-item-object'    => 'custom',
                'menu-item-url'       => home_url(),
                'menu-item-status'    => 'publish',
            ]);
            return;
        }

        if ($frontPageId) {
            wp_update_nav_menu_item(
                $menuId,
                0,
                array(
                    'menu-item-title'     => __('Home', 'kubio'),
                    'menu-item-object'    => 'page',
                    'menu-item-object-id' => $frontPageId,
                    'menu-item-type'      => 'post_type',
                    'menu-item-status'    => 'publish',
                )
            );
        }
        if ($blogPageId) {
            wp_update_nav_menu_item(
                $menuId,
                0,
                array(
                    'menu-item-title'     => __('Blog', 'kubio'),
                    'menu-item-object'    => 'page',
                    'menu-item-object-id' => $blogPageId,
                    'menu-item-type'      => 'post_type',
                    'menu-item-status'    => 'publish',
                )
            );
        }
    }





    public function backupWebsiteFrontPage()
    {

        $showOnFront = get_option('show_on_front');
        $frontPageId = get_option('page_on_front');
        $blogPageId = get_option('page_for_posts');
        $backupData = json_encode([
            'showOnFront' => $showOnFront,
            'frontPageId' => $frontPageId,
            'blogPageId' => $blogPageId
        ]);


        Flags::set($this->getFrontPageBackupKey(), $backupData);
    }


	public function backupGlobalData() {
		if(!$this->getShouldBackupData()) {
			return;
		}
		$id = kubio_global_data_post_id();
		$post                      = get_post( $id );
		if(!$post) {
			return;
		}

		$content = $post->post_content;
		Flags::set($this->getGlobalDataKey(), $content);
	}



	public function getTemplatePartContentBySlug($slug) {
		$theme = get_stylesheet();
		$source = 'kubio';
		$query_args = array(
			'post_status'    => 'publish',
			'post_type'      => 'wp_template_part',
			'name'           => $slug,
			'posts_per_page' => 1,
			'tax_query'      => array(
				array(
					'taxonomy' => 'wp_theme',
					'field'    => 'slug',
					'terms'    => $theme,
				),
			),
			'meta_query'     => array(
				array(
					'key'     => '_kubio_template_source',
					'value'   => $source,
					'compare' => '=',
				),
			),
		);
		$query = new \WP_Query($query_args);
		if (!$query->have_posts()) {
			return null;
		}
		if(count($query->posts) < 1) {
			return null;
		}

		$templatePartPost = $query->posts[0];
		return $templatePartPost->post_content;
	}

    public function backupWebsiteMenu()
    {
        $menuId =  $this->getCurrentMenuId();
        if (empty($menuId)) {
            return;
        }
        $menu_items = wp_get_nav_menu_items($menuId);
        if (empty($menu_items)) {
            return;
        }
        if ($menu_items) {
            $backup_data = [];

            foreach ($menu_items as $item) {
                $backup_data[] = [
					'id'		  => $item->ID,
                    'title'       => $item->title,
                    'url'         => $item->url,
                    'menu_order'  => $item->menu_order,
                    'parent'      => $item->menu_item_parent,
                    'type'        => $item->type,
                    'object_id'   => $item->object_id,
                    'object'      => $item->object,
                ];
            }
        }
        $jsoBackupData = json_encode($backup_data);
        Flags::set($this->getMenuBackupKey(), $jsoBackupData);
    }

    public static function getInstance()
    {
        if (! static::$instance) {
            static::$instance = new static();
        }

        return static::$instance;
    }

    public static function load()
    {
        return static::getInstance();
    }

	public function onPrintNoticeWithCheck()
	{

		if (!is_front_page() || !$this->getCurrentUserIsAdmin()) {
			return;
		}
		if (!$this->shouldShowRestoreNotice() || !$this->getHasFrontPageBackupData()) {
			return;
		}


		$this->printRestoreNotice();
	}

	public function printRestoreNotice()
	{
		echo $this->getRestoreNoticeHTML();
		echo $this->getRestoreNoticeStyle();
		echo $this->getRestoreNoticeScript();
	}
	public function getRestoreNoticeHTML()
	{
		ob_start();

		?>
		<div class="kubio-front-page-revert-popup__parent">
			<div class="kubio-front-page-revert-notice">
				<div class="kubio-front-page-revert-notice__header">
					<?php echo __('Keep the new home page?', 'kubio'); ?>
					<span class="kubio-front-page-revert-notice__header__close">&times</span>
				</div>
				<div class="kubio-front-page-revert-notice__content">
					<?php echo __(" We created a new home page for you. If you don't like it you can restore your previous home page.", 'kubio'); ?>
				</div>
				<div class="kubio-front-page-revert-notice__footer">
					<button class="kubio-front-page-revert-notice__button kubio-front-page-revert-notice__footer__keep">
						<?php echo __("Yes, keep my new home page", 'kubio'); ?>
					</button>
					<button class="kubio-front-page-revert-notice__button kubio-front-page-revert-notice__footer__restore">
						<?php echo __("Restore my previous home page", 'kubio'); ?>
					</button>
				</div>
			</div>
		</div>

		<?php

		$content = ob_get_clean();

		return $content;
	}

	public function getRestoreNoticeScript()
    {
        ob_start();

        $encodedData = Flags::get($this->getFrontPageBackupKey());
        if (empty($encodedData)) {
            return false;
        }

        $data = json_decode($encodedData, true);
        $showOnFront = $data['showOnFront'];
        $blogOnFront = $showOnFront === 'posts';
        $confirmMessage;
        if($blogOnFront) {
            $confirmMessage =  __('Your previous home page was showing the most recent blog posts. Are you sure you want to restore your previous home page?', 'kubio');
        } else {
            $confirmMessage =   __('Are you sure you want to restore your previous home page?', 'kubio');
        }
        $fetchUrl = add_query_arg(
            array(
                // 'action'   => 'kubio-remote-notifications-retrieve',
                '_wpnonce' => wp_create_nonce(static::$nonceKey),

            ),
            admin_url('admin-ajax.php')
        );

    ?>

        <script>
            (function($) {

                $(document).ready(function() {

                    const baseUrl = "<?php echo $fetchUrl; ?>";

                    const getUrl = function(action) {
                        try {
                            const urlObject = new URL(baseUrl);

                            const searchQuery = urlObject.searchParams;
                            searchQuery.append('action', action)
                            const url = urlObject.toString();
                            return url;
                        } catch (e) {
                            console.error(e);
                        }
                        return null;
                    }
                    const removeNotice = () => {
                        let container = document.querySelector('.kubio-front-page-revert-notice');
                        if (!container) {
                            return
                        }
                        container.parentNode.removeChild(container);
                    }
                    let pending = false;
                    const onKeepFrontPage = function() {
                        if (pending) {
                            return
                        }
                        pending = true;
                        removeNotice();
                        const url = getUrl('kubio_front_page_revert_action');
                        window.fetch(url)


                    }
                    const onRestoreFrontPage = function() {
                        if (!confirm("<?php echo $confirmMessage; ?>")) {
                            return
                        }
                        if (pending) {
                            return
                        }
                        pending = true;

                        removeNotice();
                        const url = getUrl('kubio_restore_front_page');
                        window.fetch(url)
                            .finally((result) => {
                                window.location.href = "<?php echo home_url(); ?>"
                            })

                    }
					debugger;
                    let keepButtons = document.querySelectorAll('.kubio-front-page-revert-notice__footer__keep, .kubio-front-page-revert-notice__header__close');
                    if (keepButtons.length > 0) {
						[...keepButtons].forEach(button => {
							button.addEventListener('click', onKeepFrontPage)
						})
                    }
                    let restoreButton = document.querySelector('.kubio-front-page-revert-notice__footer__restore');
                    if (restoreButton) {
                        restoreButton.addEventListener('click', onRestoreFrontPage)
                    }

                })
            })(jQuery)
        </script>

    <?php

        $content = ob_get_clean();

        return $content;
    }
    public function getRestoreNoticeStyle()
    {
        ob_start();
    ?>
        <style>
            .kubio-front-page-revert-notice {
                position: fixed;
                bottom: 1px;
                left: 150px;
                width: 375px;
                padding-top: 20px;
                padding-bottom: 20px;
                padding-left: 25px;
                padding-right: 25px;
                box-shadow: 0px 4px 15px 0px #00000040;
                z-index: 99999;
                background: #F4F4F7;
                display: flex;
                flex-direction: column;
                gap: 20px;
                text-align: center;
				font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;
                box-sizing: border-box;
                opacity: 0;
                animation: kubioFrontRevertPopupSlideUp 0.5s ease-out forwards;
                animation-delay: 1s;
            }

            .kubio-front-page-revert-notice__header {
                background: #007CBA;
                margin-left: -25px;
                margin-right: -25px;
                margin-top: -20px;
                padding-left: 25px;
                padding-right: 25px;
                padding-top: 20px;
                padding-bottom: 20px;
                color: white;
                font-size: 20px;
                font-weight: 700;
                text-align: center;
                line-height: 1.3;
				position: relative;


            }
			.kubio-front-page-revert-notice__header__close {
				position: absolute;
				top: 0px;
				right: 4px;
				font-size: 24px;
				padding: 5px;
				cursor: pointer;
				line-height: 1;
			}

            @keyframes kubioFrontRevertPopupSlideUp {
                from {
                    transform: translateY(100%);
                    opacity: 0;
                }
                to {
                    transform: translateY(0);
                    opacity: 1;
                }
            }

            .kubio-front-page-revert-notice__content {
                font-size: 14px;
            }

			.kubio-front-page-revert-notice__button {
				align-items: center;
				background: none;
				border: 0;
				border-radius: 2px;
				box-sizing: border-box;
				cursor: pointer;
				display: inline-flex;
				justify-content: center;
				font-family: inherit;
				font-size: 13px;
				font-weight: 400;
				height: 36px;
				margin: 0;
				padding: 6px 12px;
				text-decoration: none;
				transition: box-shadow .1s linear;
				background: #007CBA;
				outline: 1px solid #0000;
				text-decoration: none;
				text-shadow: none;
				white-space: nowrap;
				transition: 0.3s ease-in-out;
				transition-property: color, background-color;

			}
            .kubio-front-page-revert-notice__footer__keep {
				background: #007CBA;
				color: #fff;
                &:hover {
                    background-color: #006ba1;
                    color: #fff;
                }
            }
			.kubio-front-page-revert-notice__footer__restore {
				background: #cc1818;
				color: #fff;
				&:hover {
					background-color: #9e1313;
				}
			}


            .kubio-front-page-revert-notice__footer {
                display: flex;
                flex-direction: column;
                gap: 10px;
            }
        </style>
<?php
        return ob_get_clean();
    }
}

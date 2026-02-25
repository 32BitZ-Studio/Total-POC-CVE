<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Hint</h3>
    <p>1. All plugins are installed in the /wp-content/plugins/ folder, so
        <br>so if after activation the site gives an error (white screen), 
        <br>then just go to FTP and deactivate the conflicting plugin by substituting
        <br>a number/letter in the name of its folder. To resume its operation,
        <br>go to the site's admin panel and click "Activate" next to the plugin.</p>
    <p>2. To view the mobile version
		<br>in browsers running on the Chromium engine (Google Chrome, Yandex, Opera):
        <br>&nbsp; &nbsp;A. Open the developer panel (press " F12")
		<br>&nbsp; &nbsp;B. Select the resolution template in the "Responsive" section,
		<br>&nbsp; &nbsp;or set the required width/height, specify the screen orientation
		<br>in browsers running on the Gecko engine (Firefox, Waterfox, Avant Browser):
		<br>&nbsp; &nbsp;A. Open the adaptive design mode (Ctrl+Shift+M combination)
		<br>&nbsp; &nbsp;B. Specify the screen orientation and select a resolution template,
		<br>&nbsp; &nbsp;or set the desired width/height
		</p>
</div>

<h2>Step 6/7. <span class="name">Additional settings</span></h2>
        <font color="red"><strong>ATTENTION:</strong></font>
		Part of the text is translated into English using a machine algorithm. As you develop, all materials will be of better quality.<br><br>
		
<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Important:</strong><br>
        The tools presented in this section allow you to simplify implementations, expand management capabilities, or work out the Frontend component of the site. Before using them to eliminate errors, read the official instructions/recommendations in the WordPress repository.
	</p>
</div>

<table class="widefat table-not-full-width plugins">
    <thead>
    <tr>
        <th style="width:100px">Service</th>
        <th>Destination</th>
		<th>Language</th>
        <th>Recommendations</th>
    </tr>
    </thead>
    <tbody>
    <tr class="inactive">
        <td><a href="https://search.google.com/test/mobile-friendly" target="_blank">Google Search Console</a></td>
        <td>Check for adaptability to mobile devices, preview 1 screen and study the code<br><strong>Analog:</strong> <a href="https://www.bing.com/webmaster/tools/mobile-friendliness" target="_blank">Checking from Microsoft Bing</a>
        </td>
		<td>RUS
		</td>
        <td>Eliminate errors
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://bluetree.ai/screenfly/" target="_blank">Screenfly</a></td>
        <td>Checking the site display under different permissions<br><strong>Analogs:</strong> <a href="http://adaptivator.ru/" target="_blank">Adaptivator</a> и <a href="https://chrome.google.com/webstore/detail/i-love-adaptive-–-mobiler/dpfgmabfakicdmcijnddgbelfhfkddnb" target="_blank">I love adaptive (extension for Chrome)</a><br><strong>Recommend:</strong> <a href="https://blisk.io/" target="_blank">Blisk (browser) - display mobile/PC versions in realtime</a>
        </td>
		<td>ENG
		</td>
        <td>Eliminate errors
        </td>
    </tr>
    </tbody>
</table>

<h3>I. Plugins for acceleration</h3>
<p>Install plugins corresponding to the required tasks</p>

<?php

$titles = array('Plugin', 'Status', 'Analogs', 'Replace by code', 'Objective', 'Module importance', 'Control', 'Installation instruction');
$plugins = array(
    array(
        'name' => 'WPtouch',
        'icon' => WP01_Content::get_image_src('icons/6/wptouch_m.jpg'),
        'path' => 'wptouch/wptouch.php',
        'analogs' =>  array(
            array(
                'name' => 'WordPress Mobile Pack — Mobile Plugin for Progressive Web Apps & Hybrid Mobile Apps',
                'icon' => WP01_Content::get_image_src('icons/6/wordpress-mobile-pack_s.jpg'),
                'path' => 'wordpress-mobile-pack/wordpress-mobile-pack.php',
                'settings_link'  => '/admin.php?page=wmp-options',
            ),
            array(
                'name' => 'Jetpack от WordPress.com',
                'icon' => WP01_Content::get_image_src('icons/6/jetpack_s.jpg'),
                'path' => 'jetpack/jetpack.php',
				'settings_link'  => '/admin.php?page=jetpack',
            )
        ),
        'desc' => 'Implementation of mobile version to the website',
		'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br>Documentation:<br> 
<a href="https://support.wptouch.com/category/1402-category" target = "_blank"><strong>ENG</strong></a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/admin.php?page=wptouch-admin-general-settings',
    ),
    array(
        'name' => 'Manager of Wordpress updates (Disable updates, Disable automatical updates)',
        'icon' => WP01_Content::get_image_src('icons/6/webcraftic-updates-manager_m.jpg'),
        'path' => 'webcraftic-updates-manager/webcraftic-updates-manager',
        'analogs' =>  array(
            array(
                'name' => 'Easy Updates Manager',
                'icon' => WP01_Content::get_image_src('icons/6/stops-core-theme-and-plugin-updates_s.jpg'),
				'path' => 'stops-core-theme-and-plugin-updates/main.php',
                'settings_link'  => '/index.php?page=mpsum-update-options',
            ),
            array(
                'name' => 'Disable All WordPress Updates',
                'icon' => WP01_Content::get_image_src('icons/6/disable-wordpress-updates_s.jpg'),
                'path' => 'disable-wordpress-updates/disable-updates.php',
				'settings_link'  => '',
            )
        ),
        'desc' => 'Controling of automatic theme / plugin / CMS / translation updates',
		'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=updates-wbcr_updates_manager',
    ),
    array(
        'name' => 'LuckyWP Scripts Control',
        'icon' => WP01_Content::get_image_src('icons/6/luckywp-scripts-control_m.jpg'),
        'path' => 'luckywp-scripts-control/luckywp-scripts-control.php',
        'analogs' =>  array(
            array(
                'name' => 'Header and Footer Scripts',
                'icon' => WP01_Content::get_image_src('icons/6/header-and-footer-scripts_s.jpg'),
                'path' => 'header-and-footer-scripts/shfs.php',
                'settings_link'  => '/options-general.php?page=header-and-footer-scripts%2Fshfs.php',
            ),
            array(
                'name' => 'DCO Insert Analytics Code',
                'icon' => WP01_Content::get_image_src('icons/6/dco-insert-analytics-code_s.jpg'),
                'path' => 'dco-insert-analytics-code/dco-insert-analytics-code.php',
				'settings_link'  => '/options-general.php?page=dco-insert-analytics-code',
            ),
            array(
                'name' => 'Head, Footer and Post Injections',
                'icon' => WP01_Content::get_image_src('icons/6/header-footer_s.jpg'),
                'path' => 'header-footer/plugin.php',
				'settings_link'  => '/options-general.php?page=header-footer%2Foptions.php',
            )
        ),
        'desc' => 'Comfortable adding of code to the head/body areas of the site',
		'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=lwpsc_scripts',
    ),
    array(
        'name' => 'Code Snippets',
        'icon' => WP01_Content::get_image_src('icons/6/code-snippets_m.jpg'),
        'path' => 'code-snippets/code-snippets.php',
        'analogs' =>  array(
            array(
                'name' => 'Woody ad snippets — Insert Header Footer Code, AdSense Ads',
                'icon' => WP01_Content::get_image_src('icons/6/widget-output-cache_s.jpg'),
                'path' => 'widget-output-cache/widget-output-cache.php',
                'settings_link'  => '/edit.php?post_type=wbcr-snippets',
            ),
            array(
                'name' => 'My Custom Functions',
                'icon' => WP01_Content::get_image_src('icons/6/my-custom-functions_s.jpg'),
                'path' => 'my-custom-functions/my-custom-functions.php',
				'settings_link'  => '/options-general.php?page=my-custom-functions',
            )
        ),
        'desc' => 'Managing code snippets (virtual functions.php)',
		'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/admin.php?page=snippets',
		'code_replace' => '
<strong>Замена функции &quot;Виртуальный functions.php&quot;:</strong><br>
1. Перейдите в директорию плагинов вашего сайта (/wp-content/plugins/)<br>
2. Создайте папку с именем вашего плагина, например "virtual-functions"<br>
3. В этой папке создайте файл с расширением php, например "my-plugin.php"<br>
4. Разместите в файле следующий код:<br>
<div class="tc">
&lt;?php<br>
/*<br>
Plugin Name: WP01: виртуальный functions.php<br>
Description: Пользовательские коды, размещенные вручную в файле /wp-content/plugins/virtual-functions/my-plugin.php<br>
Version: 16.04.2020<br>
*/<br>
/* Начало кода 1 */<br>
/* Конец кода 1 */<br>
<br>
/* Начало кода 2 */<br>
/* Конец кода 2 */<br>
?&gt;<br>
</div>
5. Разместите необходимый пользовательский код. Для удобства чтения рекомендуем вставлять код между условных разделителей "Начало/Конец кода"<br>
6. В админ панели сайта выберите "Плагины" и активируйте плагин с указанным именем (например, WP01: виртуальный functions.php)
<br><br>
 
<strong>Примечание:</strong><br>
1. Если после активации плагина сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
		'
    ),
    array(
        'name' => 'WP Rollback',
        'icon' => WP01_Content::get_image_src('icons/6/wp-rollback_m.jpg'),
        'path' => 'wp-rollback/wp-rollback.php',
        'desc' => 'Installing the desired theme/plugin version from the WordPress repository. All settings are saved',
		'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br>Documentation:<br> 
<a href="https://github.com/impress-org/wp-rollback/wiki" target = "_blank"><strong>ENG</strong></a>',
        'settings_text' => 'Active, use the "Rollback" next to the plugins',
        'settings_link'  => '',
    ),
    array(
        'name' => 'WP Downgrade | Specific Core Version',
        'icon' => WP01_Content::get_image_src('icons/6/wp-downgrade_m.jpg'),
        'path' => 'wp-downgrade/wp-downgrade.php',
        'desc' => 'Updating / rolling back the CMS to the desired version from the WordPress repository. All settings are saved. <a href="https://wordpress.org/news/category/releases/" target="_blank">CMS version history</a>',
		'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=wp_downgrade',
	),		
    array(
        'icon' => WP01_Content::get_image_src('icons/3/media-cleaner_m.jpg'),
        'name' => 'Media Cleaner — Clean & Optimize Space',
        'path' => 'media-cleaner/media-cleaner.php',
        'analogs' =>  array(
            array(
                'name' => 'WPS Cleaner',
                'icon' => WP01_Content::get_image_src('icons/3/wps-cleaner_s.jpg'),
                'path' => 'wps-cleaner/wps-cleaner.php',
                'settings_link'  => '',
            )
        ),
        'desc' => 'Clearing the site of unused media files (originals and automatically created dimensions)<br> <strong>Recommend:</strong> <a href="https://wordpress.org/plugins/my-simple-space/" target="_blank">Find out the disk space used</a>',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link' => '/upload.php?page=wpmc_dashboard',
    )
);

WP01_Table::the_table($titles, $plugins);

?>

<h3>II. Quick backup</h3>
<p>Before manual code implementations, we strongly recommend making a backup copy of the files that will be edited</p>

<?php 
/* start new */
$titles = array('Name', 'Location', 'Appointment', 'Management');
    
        $structure = array(
/*
            array(
                "filename" => '.htaccess',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'Additional Web Server configuration file',
                "button_text" => 'Download'
            ),
            array(
                "filename" => 'wp-config.php',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'WordPress Configuration File',
                "button_text" => 'Download'
                
            ),
*/
            array(
                "filename" => 'footer.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'The lower part of the site template',
                "button_text" => 'Download'
            ),
            array(
                "filename" => 'header.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'The top part of the website template',
                "button_text" => 'Download'
            ),
            array(
                "filename" => 'functions.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Theme file with custom functions',
                "button_text" => 'Download'
            )
        );

    WP01_Table::build_backup_table($titles, $structure); 
	/* end new */
?>

<h3>III. Manual implementations</h3>
<p>Install/edit the code according to the required task</p>

<h4>1. Analyze the log file</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Find the overloads in the log file</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Follow these steps:</strong><br>
1. Download the program <a href="https://404.su/soft/logmaster.rar">Logmaster</a> (<a href="https://wp01.ru/programs/logmaster.rar">alternative link</a>) <br>
2. Run Logmaster and upload (Log-файл -> Загрузить) to the software log file from your server<br>
&nbsp; &nbsp; Options for getting log:<br>
&nbsp; &nbsp; - on the hosting, in the "/logs" folder or similar (depends on the hoster)<br>
&nbsp; &nbsp; - in the control panel. For example, in ISP: WWW - > Logs<br>
&nbsp; &nbsp; - request from the hoster's technical support<br>
3. In the right list of the program (Результат), examine the ip addresses in the column "%"<br>
4. Filter the left list by the selected ip (via "отобразить по ip") to get information on requests from the specified address.<br>
5. Make a decision to block the ip address or restrict access to the site files.<br>
<br><strong>Note:</strong><br>
1. To work with large lists and sort them more easily, use Excel export: Отчёты -> Лог-файл -> Excel<br>

    </div>
</div>

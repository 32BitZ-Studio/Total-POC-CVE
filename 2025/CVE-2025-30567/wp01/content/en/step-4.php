<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>

<div class="card tip">
    <h3>Hint</h3>

    <p>1. We recommend that you start protecting your site by updating
		<br>the CMS/plugins/theme. Most of the hidden gaps lie in the outdated code.</p>
    <p>2. Some of the protections, if used incorrectly, can block elements 
		<br>(for example, YouTube videos), lead to a breach, or cause the site to malfunction. 
		<br>We recommend that you perform a detailed review of the content and functional
		<br>part after each implementation.</p>
	<p>3. If you encounter difficulties in installing the code, or unexpected 
		<br>errors occur, contact the hoster's technical support, describing in detail what 
		<br>you are doing, why and what exactly is not working. In most cases, you will 
		<br>be helped or prompted to make the right decision. If you get only a 
		<br>standard unsubscribe like "not in our competence" or "contact 
		<br>the site developer" - consider another hosting provider, for example <a href="https://www.reg.ru/hosting/?rlink=reflink-6247477" target="_blank">reg.ru</a></p>
    <p>4. All plugins are installed in the folder / wp-content/plugins/  so if after 
		<br>activation, the site will give an error (white screen), then just go to FTP 
		<br>and deactivate the conflicting plugin, substituting a number/letter 
		<br>in the name of its folder. To resume its work, go to the site's admin panel
		<br>and click "Activate" next to the plugin.</p>
</div>

<h2>Step 4/7. <span class="name">Spam and hacking protection</span></h2>
        <font color="red"><strong>ATTENTION:</strong></font>
		Part of the text is translated into English using a machine algorithm. As you develop, all materials will be of better quality.<br><br>
		
<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Important:</strong><br>
        Without studying the code of the website/plugins/themes can only be determined explicit error protection. 
		We recommend that you eliminate the maximum number of identified gaps/comments, and install blockers/firewalls/scanners to prevent possible external influences on your project. 
		Start working on protection by studying HTTP headers and scanning the Frontend part of the site for viruses.
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
        <td><a href="https://securityheaders.com/" target="_blank">Security Headers</a></td>
        <td>HTTP header analyzer with their display and comments.
        </td>
		<td>ENG
		</td>
        <td>Strive to correct all comments
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://seolik.ru/security-headers" target="_blank">SeoLik</a></td>
        <td>Testing the main HTTP headers of the site that affect the level of protection against various Internet attacks.
        </td>
		<td>RUS
		</td>
        <td>Strive to correct all comments
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://www.virustotal.com" target="_blank">VirusTotal</a></td>
        <td>Scan files/URL / IP based on 83 offline / online antivirus programs.<br><strong>Basic scanners:</strong> <a href="https://yandex.com/safety/" target="_blank">Yandex Safe Browsing</a> (<a href="https://yandex.com/support/search/beware/harmful-sites.html" target="_blank">reference</a>) и <a href="https://transparencyreport.google.com/safe-browsing/search" target="_blank">Google Safe Browsing</a> (<a href="https://safebrowsing.google.com/" target="_blank">reference</a>)
        </td>
		<td>ENG
		</td>
        <td>Take care of the absence of viruses on the site
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://encoder.till.im/scanner" target="_blank">Email scanner</a></td>
        <td>Email address protection scanner from spam on the site page.<br><strong>Manual decoder:</strong> <a href="http://www.wbwip.com/wbw/emailencoder.html" target="_blank">http://www.wbwip.com/wbw/emailencoder.html</a>
        </td>
		<td>ENG
		</td>
        <td>Protect Email addresses from spam
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://www.mail-tester.com/" target="_blank">Mail Tester</a></td>
        <td>Testing the receipt of emails by a third-party user with a number of authenticity checks<br><strong>Recommend:</strong> <a href="https://mxtoolbox.com/blacklists.aspx" target="_blank">checking the site's ip in 100+ blacklists</a>, and also <a href="https://2ip.ru/lookup/" target="_blank">determining the site's ip address</a>
        </td>
		<td>RUS
		</td>
        <td>Fix bugs and exclude from spamlists
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
        'name' => 'No CAPTCHA reCAPTCHA',
        'icon' => WP01_Content::get_image_src('icons/4/no-captcha-recaptcha_m.jpg'),
        'path' => 'no-captcha-recaptcha/no-captcha-recaptcha.php',
        'analogs' =>  array(
            array(
                'name' => 'reCaptcha by BestWebSoft',
                'icon' => WP01_Content::get_image_src('icons/4/google-captcha_s.jpg'),
                'path' => 'google-captcha/google-captcha.php',
                'settings_link'  => '/admin.php?page=google-captcha.php',
            ),
            array(
                'name' => 'Advanced noCaptcha & invisible Captcha (v2 & v3)',
                'icon' => WP01_Content::get_image_src('icons/4/advanced-nocaptcha-recaptcha_s.jpg'),
                'path' => 'advanced-nocaptcha-recaptcha/advanced-nocaptcha-recaptcha.php',
				'settings_link'  => '/options-general.php?page=anr-admin-settings',
            ),
            array(
                'name' => 'Login No Captcha reCAPTCHA',
                'icon' => WP01_Content::get_image_src('icons/4/login-nocaptcha_s.jpg'),
                'path' => 'login-recaptcha/login-nocaptcha.php',
				'settings_link'  => '/options-general.php?page=login-recaptcha%2Fadmin.php',
            )
        ),
        'desc' => 'Implements Google reCAPTCHA to spam / hacking vulnerable pages',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=ncr-config',
    ),
    array(
        'name' => 'All In One WP Security',
        'icon' => WP01_Content::get_image_src('icons/4/all-in-one-wp-security-and-firewall_m.jpg'),
        'path' => 'all-in-one-wp-security-and-firewall/wp-security.php',
        'analogs' =>  array(
            array(
                'name' => 'iThemes Security (ранее Better WP Security)',
                'icon' => WP01_Content::get_image_src('icons/4/better-wp-security_s.jpg'),
                'path' => 'better-wp-security/better-wp-security.php',
                'settings_link'  => '/admin.php?page=itsec',
            ),
            array(
                'name' => 'Wordfence Security — Firewall & Malware Scan',
                'icon' => WP01_Content::get_image_src('icons/4/wordfence_s.jpg'),
                'path' => 'wordfence/wordfence.php',
				'settings_link'  => '/admin.php?page=Wordfence',
            ),
            array(
                'name' => 'Cerber Security, Antispam & Malware Scan',
                'icon' => WP01_Content::get_image_src('icons/4/wp-cerber_s.jpg'),
                'path' => 'wp-cerber/wp-cerber.php',
				'settings_link'  => '/admin.php?page=cerber-security',
            )
        ),
        'desc' => 'Customizable all-round protection against all major threats',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br>Documentation:<br> 
<a href="https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin" target = "_blank"><strong>ENG</strong></a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/admin.php?page=aiowpsec_settings',
    ),
    array(
        'name' => 'WP Content Copy Protection & No Right Click',
        'icon' => WP01_Content::get_image_src('icons/4/wp-content-copy-protector_m.jpg'),
        'path' => 'wp-content-copy-protector/preventer-index.php',
        'analogs' =>  array(
            array(
                'name' => 'WP-CopyProtect [Protect your blog posts]',
                'icon' => WP01_Content::get_image_src('icons/4/wp-copyprotect_s.jpg'),
                'path' => 'wp-copyprotect/wp-copyprotect.php',
                'settings_link'  => '/admin.php?page=wpcopyprotect',
            ),
            array(
                'name' => 'WP Content Copy Protection with Color Design',
                'icon' => WP01_Content::get_image_src('icons/4/wp-copy-protect-with-color-design_s.jpg'),
                'path' => 'wp-copy-protect-with-color-design/wp_copy_design.php',
				'settings_link'  => '/options-general.php?page=WP_Copy_Protection_admin_menu',
            ),
            array(
                'name' => 'Secure Copy Content Protection',
                'icon' => WP01_Content::get_image_src('icons/4/secure-copy-content-protection_s.jpg'),
                'path' => 'secure-copy-content-protection/secure-copy-content-protection.php',
				'settings_link'  => '/admin.php?page=secure-copy-content-protection',
            )
        ),
        'desc' => 'Allows you to lock the right mouse button and implement some copy protection',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=wccpoptionspro',
    ),
    array(
        'name' => 'wp_head() cleaner',
        'icon' => WP01_Content::get_image_src('icons/4/wp-head-cleaner_m.jpg'),
        'path' => 'wp-head-cleaner/wp-head-cleaner.php',
        'analogs' =>  array(
			array(
				'name' => 'Nietzsche — WP Head Cleaner',
				'icon' => WP01_Content::get_image_src('icons/4/nietzsche_s.jpg'),
				'path' => 'nietzsche/nietzsche.php'
            ),
            array(
                'name' => 'WP Clean Head',
                'icon' => WP01_Content::get_image_src('icons/4/wp-clean-head_s.jpg'),
                'path' => 'wp-clean-head/wp-clean-head.php',
				'settings_link'  => '',
            )
        ),
        'desc' => 'Disabling of unnecessary tags/links/meta in head section',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=wp_head_cleaner',
		'code_replace' => '
<strong>Замена функции &quot;Отключение XML-RPC&quot;:</strong><br>
<strong>Метод № 1</strong><br>
1. Откройте файл .htaccess находящийся в корне сайта<br>
2. Добавьте код<br>
<div class="tc">
# WP01: блокировка xmlrpc.php запросов<br>
&lt;Files xmlrpc.php&gt;<br>
order deny,allow<br>
deny from all<br>
&lt;/Files&gt;<br>
</div>
<strong>Метод № 2</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: блокировка xmlrpc.php запросов<br>
add_filter(&#039;xmlrpc_enabled&#039;, &#039;__return_false&#039;);<br><br>
</div>

<strong>Замена функции &quot;Удаление ссылок Windows Live Writer&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление ссылок Windows Live Writer<br>
remove_action(&#039;wp_head&#039;, &#039;wlwmanifest_link&#039;);<br><br>
</div>

<strong>Замена функции &quot;Удаление отображения WordPress версии&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление ображения WordPress версии<br>
	// Удаление версии WordPress со страниц, RSS, скриптов и стилей<br>
add_filter(&#039;the_generator&#039;, &#039;__return_empty_string&#039;);<br>
function rem_wp_ver_css_js( $src ) {<br>
    if ( strpos( $src, &#039;ver=&#039; ) )<br>
        $src = remove_query_arg( &#039;ver&#039;, $src );<br>
    return $src;<br>
}<br>
add_filter( &#039;style_loader_src&#039;, &#039;rem_wp_ver_css_js&#039;, 9999 );<br>
add_filter( &#039;script_loader_src&#039;, &#039;rem_wp_ver_css_js&#039;, 9999 );<br>
	// Удаление версии WP из футера админки<br>
function kill_footer_version ($default) {<br>
return &#039;&#039;;<br>
}<br>
add_filter (&#039;update_footer&#039;, &#039;kill_footer_version&#039;, 999);<br>
	// Удаление сообщений &quot;Спасибо, что выбрали WordPress&quot;<br>
 function kill_footer_filter ($default) {<br>
return &#039;&#039;;<br>
}<br>
add_filter (&#039;admin_footer_text&#039;, &#039;kill_footer_filter&#039;);<br><br>
</div>

<strong>Замена функции &quot;Удаление Shortlinks&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление Shortlinks<br>
remove_action( &#039;wp_head&#039;, &#039;wp_shortlink_wp_head&#039; );<br><br>
</div>

<strong>Замена функции &quot;Отключение Emoji&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Удаление Emoji<br>
remove_action( &#039;wp_head&#039;, &#039;print_emoji_detection_script&#039;, 7 );<br>
remove_action( &#039;admin_print_scripts&#039;, &#039;print_emoji_detection_script&#039; );<br>
remove_action( &#039;wp_print_styles&#039;, &#039;print_emoji_styles&#039; );<br>
remove_action( &#039;admin_print_styles&#039;, &#039;print_emoji_styles&#039; );<br>
remove_filter( &#039;the_content_feed&#039;, &#039;wp_staticize_emoji&#039; );<br>
remove_filter( &#039;comment_text_rss&#039;, &#039;wp_staticize_emoji&#039; );<br>
remove_filter( &#039;wp_mail&#039;, &#039;wp_staticize_emoji_for_email&#039; );<br>
add_filter( &#039;tiny_mce_plugins&#039;, &#039;disable_wp_emojis_in_tinymce&#039; );<br>
function disable_wp_emojis_in_tinymce( $plugins ) {<br>
    if ( is_array( $plugins ) ) {<br>
        return array_diff( $plugins, array( &#039;wpemoji&#039; ) );<br>
    } else {<br>
        return array();<br>
    }<br>
}<br><br>
</div>

<strong>Замена функции &quot;Отключение REST API&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Отключение REST API<br>
add_filter( &#039;rest_authentication_errors&#039;, &#039;code_disable_rest_api&#039; );<br>
function code_disable_rest_api( $access ) {<br>
	return new WP_Error( &#039;rest_disabled&#039;, __( &#039;REST API disabled&#039; ), array( &#039;status&#039; =&gt; rest_authorization_required_code() ) );<br>
}<br>
</div>
3. Проверьте отключение добавив в URL значение wp-json (например, https://wp01.ru/wp-json) - если в открывшейся странице будет короткая строка, значит REST API отключен<br><br>

<strong>Замена функции &quot;Отключение oEmbed&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте код<br>
<div class="tc">
# WP01: Отключение oEmbed<br>
function disable_embeds_code_init() {<br>
	// Удаляем REST API<br>
remove_action( &#039;rest_api_init&#039;, &#039;wp_oembed_register_route&#039; );<br>
	// Выключаем обнаружение oEmbed<br>
add_filter( &#039;embed_oembed_discover&#039;, &#039;__return_false&#039; );<br>
	// Не фильтруем результаты oEmbed<br>
remove_filter( &#039;oembed_dataparse&#039;, &#039;wp_filter_oembed_result&#039;, 10 );<br>
	// Удаляем ссылки oEmbed<br>
remove_action( &#039;wp_head&#039;, &#039;wp_oembed_add_discovery_links&#039; );<br>
	// Удаляем oembed JavaScript из интерфейса и бэк-энда.<br>
remove_action( &#039;wp_head&#039;, &#039;wp_oembed_add_host_js&#039; );<br>
add_filter( &#039;tiny_mce_plugins&#039;, &#039;disable_embeds_tiny_mce_plugin&#039; );<br>
	// Удаляем все правила перезаписи<br>
add_filter( &#039;rewrite_rules_array&#039;, &#039;disable_embeds_rewrites&#039; );<br>
	// Удаляем фильтр результата oEmbed перед выполнением HTTP-запросов<br>
 remove_filter( &#039;pre_oembed_result&#039;, &#039;wp_filter_pre_oembed_result&#039;, 10 );<br>
}<br>
add_action( &#039;init&#039;, &#039;disable_embeds_code_init&#039;, 9999 );<br>
function disable_embeds_tiny_mce_plugin($plugins) {<br>
    return array_diff($plugins, array(&#039;wpembed&#039;));<br>
}<br>
function disable_embeds_rewrites($rules) {<br>
    foreach($rules as $rule =&gt; $rewrite) {<br>
        if(false !== strpos($rewrite, &#039;embed=true&#039;)) {<br>
            unset($rules[$rule]);<br>
        }<br>
    }<br>
    return $rules;<br>
}<br><br>
</div>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'name' => 'Antispam Bee',
        'icon' => WP01_Content::get_image_src('icons/4/antispam-bee_m.jpg'),
        'path' => 'antispam-bee/antispam_bee.php',
        'analogs' =>  array(
            array(
                'name' => 'Anti-spam',
                'icon' => WP01_Content::get_image_src('icons/4/anti-spam_s.jpg'),
                'path' => 'anti-spam/anti-spam.php',
                'settings_link'  => '/options-general.php?page=anti-spam',
            ),
            array(
                'name' => 'WordPress Zero Spam',
                'icon' => WP01_Content::get_image_src('icons/4/zero-spam_s.jpg'),
                'path' => 'zero-spam/zero-spam.php',
                'settings_link'  => '/options-general.php?page=zerospam',
            ),
            array(
                'name' => 'WPBruiser {no- Captcha anti-Spam}',
                'icon' => WP01_Content::get_image_src('icons/4/goodbye-captcha_s.jpg'),
                'path' => 'goodbye-captcha/goodbye-captcha.php',
                'settings_link'  => '/admin.php?page=wp-bruiser-settings',
            )
        ),
        'desc' => 'Good spam blocking',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br>Documentation:<br> 
<a href="https://antispambee.pluginkollektiv.org/documentation/" target = "_blank"><strong>ENG</strong></a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=antispam_bee',
    ),
    array(
        'name' => 'HTTP Headers',
        'icon' => WP01_Content::get_image_src('icons/4/http-headers_m.jpg'),
        'path' => 'http-headers/http-headers.php',
        'analogs' =>  array(
            array(
                'name' => 'Security Headers',
                'icon' => WP01_Content::get_image_src('icons/4/security-headers_s.jpg'),
                'path' => 'security-headers/security_headers.php',
                'settings_link'  => '/options-general.php?page=security_headers',
            ),
            array(
                'name' => 'HTTP headers to improve web site security',
                'icon' => WP01_Content::get_image_src('icons/4/http-security_s.jpg'),
                'path' => 'http-security/http-security.php',
                'settings_link'  => '/options-general.php?page=http-security',
            )
        ),
        'desc' => 'Protecting of HTTP headers',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a><br> Documentation from Mozilla:<br> <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" target = "_blank"><strong>ENG</strong></a><br>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=security_headers',
		'code_replace' => '<strong>Универсальные настройки для Apache:</strong><br>
1. Откройте файл .htaccess находящийся в корне сайта<br>
2. Добавьте код:<br>
<div class="tc">
&lt;IfModule mod_headers.c&gt;<br>
  Header always set X-Content-Type-Options &quot;nosniff&quot;<br>
  &lt;FilesMatch &quot;\.(php|html)$&quot;&gt;<br>
    Header set X-Frame-Options &quot;DENY&quot;<br>
    Header set X-XSS-Protection &quot;1; mode=block&quot;<br>
    Header set X-Permitted-Cross-Domain-Policies &quot;none&quot;<br>
    Header set Strict-Transport-Security &quot;max-age=31536000; includeSubDomains; preload&quot; env=HTTPS<br>
    Header set Content-Security-Policy-Report-Only &quot;default-src &#039;self&#039;; <br>
	script-src &#039;self&#039; &#039;unsafe-inline&#039; &#039;unsafe-eval&#039; https://vk.com https://*.vk.com https://www.googletagmanager.com https://*.yandex.ru https://yandex.ru https://www.youtube.com https://www.google-analytics.com https://www.gstatic.com https://*.gstatic.com https://www.google.com https://*.google.com https://*.googleapis.com <font color="red">https://sait.ru;</font> <br>
	style-src &#039;self&#039; &#039;unsafe-inline&#039; &#039;unsafe-eval&#039; https://fonts.googleapis.com/ https://cdnjs.cloudflare.com; <br>
	img-src &#039;self&#039; * data:; <br>
	connect-src &#039;self&#039; *; <br>
	frame-src &#039;self&#039; https://vk.com https://*.vk.com https://www.googletagmanager.com https://*.yandex.ru https://yandex.ru https://www.youtube.com https://www.google-analytics.com https://www.gstatic.com https://*.gstatic.com https://www.google.com https://*.google.com https://*.googleapis.com <font color="red">https://sait.ru;</font> <br>
	object-src &#039;self&#039; *; <br>
	font-src &#039;self&#039; * data:; <br>
	media-src *; <br>
	form-action &#039;self&#039;;&quot;; <br>
    Header set Referrer-Policy &quot;no-referrer-when-downgrade&quot;<br>
    Header set Permissions-Policy &quot;document-domain=(), fullscreen=(self), geolocation=(self)&quot;<br>
  &lt;/FilesMatch&gt;<br>
&lt;/IfModule&gt;<br>
</div>

<br><strong>Универсальные настройки для Nginx:</strong><br>
1. Правки необходимо вносить в файл nginx.conf, расположенный на сервере по пути /etc/nginx/nginx.conf<br>
2. После внесения настроек необходимо перезагрузить сервер. Проще и безопаснее это сделать выключив, а затем включив сайт в разделе "WWW-домены" (для ISPmanager)<br>
3. Ошибка в файле nginx.conf может нарушить работу сайта. Не вносите изменения, если вы не в полной мере уверены в них!<br>
4. Добавьте код:<br>
<div class="tc">
	add_header &quot;X-Frame-Options&quot; &quot;DENY&quot;;<br>
	add_header &quot;X-XSS-Protection&quot; &quot;1; mode=block&quot;;<br>
	add_header &quot;X-Content-Type-Options&quot; &quot;nosniff&quot;;<br>
	add_header &quot;Strict-Transport-Security&quot; &quot;max-age=31536000; includeSubDomains; preload&quot;;<br>
	add_header &quot;Referrer-Policy&quot; &quot;no-referrer-when-downgrade&quot;;<br>
	add_header &quot;Content-Security-Policy&quot;<br>
	&quot;default-src &#039;self&#039;; <br>
	script-src &#039;self&#039; &#039;unsafe-inline&#039; &#039;unsafe-eval&#039; https://vk.com https://*.vk.com https://www.googletagmanager.com https://*.yandex.ru https://yandex.ru https://www.youtube.com https://www.google-analytics.com https://www.gstatic.com https://*.gstatic.com https://www.google.com https://*.google.com https://*.googleapis.com <font color="red">https://sait.ru;</font> <br> 
	style-src &#039;self&#039; &#039;unsafe-inline&#039; &#039;unsafe-eval&#039; https://fonts.googleapis.com/ https://cdnjs.cloudflare.com; <br>
	img-src &#039;self&#039; * data:; <br>
	connect-src &#039;self&#039; *; <br>
	frame-src &#039;self&#039; https://vk.com https://*.vk.com https://www.googletagmanager.com https://*.yandex.ru https://yandex.ru https://www.youtube.com https://www.google-analytics.com https://www.gstatic.com https://*.gstatic.com https://www.google.com https://*.google.com https://*.googleapis.com <font color="red">https://sait.ru;</font> <br>
	object-src &#039;self&#039; *; <br>
	font-src &#039;self&#039; * data:; <br>
	media-src *; <br>
	form-action &#039;self&#039;;&quot;;<br>
	add_header &quot;Permissions-Policy&quot; &quot;document-domain=(), fullscreen=(self), geolocation=(self)&quot;;<br>
	add_header &quot;X-Permitted-Cross-Domain-Policies&quot; &quot;none&quot;;<br><br>
</div>

<strong>Примечание:</strong><br>
1. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)<br>
2. При ошибки в Nginx возможно потребуется связаться с техподдержкой хостинга (вероятность этого высока на старых версиях ISPmanager, которые имеют недочёты в проверки кода)
		'
    ),
    array(
        'name' => 'AntiSpambot',
        'icon' => WP01_Content::get_image_src('icons/4/antispambot_m.jpg'),
        'path' => 'antispam-bot/antispambot.php',
        'analogs' =>  array(
            array(
                'name' => 'Email Encoder — Protect Email Addresses',
                'icon' => WP01_Content::get_image_src('icons/4/email-encoder-bundle_s.jpg'),
                'path' => 'email-encoder-bundle/email-encoder-bundle.php',
                'settings_link'  => '/options-general.php?page=email-encoder-bundle-option-page',
            ),
            array(
                'name' => 'Email Address Encoder',
                'icon' => WP01_Content::get_image_src('icons/4/email-address-encoder_s.jpg'),
                'path' => 'email-address-encoder/email-address-encoder.php',
                'settings_link'  => '/options-general.php?page=email-address-encoder',
            ),
            array(
                'name' => 'Simple Mail Address Encoder',
                'icon' => WP01_Content::get_image_src('icons/4/simple-mail-address-encoder_s.jpg'),
                'path' => 'simple-mail-address-encoder/simple-mail-address-encoder.php',
                'settings_link'  => '',
            )
        ),
        'desc' => 'Protecting email addresses from spam bots by encoding a code',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'Activated, put email in shortcode: <br>[nospam] [/nospam]',
        'settings_link'  => '',
    ),
    array(
        'name' => 'Anti-Spam by CleanTalk',
        'icon' => WP01_Content::get_image_src('icons/4/cleantalk-spam-protect_m.jpg'),
        'path' => 'cleantalk-spam-protect/cleantalk.php',
        'analogs' =>  array(
            array(
                'name' => 'Akismet Anti-Spam',
                'icon' => WP01_Content::get_image_src('icons/4/akismet_s.jpg'),
                'path' => 'akismet/akismet.php',
                'settings_link'  => '/options-general.php?page=akismet-key-config',
            )
        ),
        'desc' => 'Span protection that allows you to not use captcha, reduces hosting load.',
        'rate' => 3,
        'link' => '<a href="https://cleantalk.org/ru/?pid=255609" class="button button-green" target = "_blank">Registrate</a><br>'.
                  'Buying of license is required, there is testing period + bonuses.',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=cleantalk',
    ),
    array(
        'name' => 'Append Link on Copy',
        'icon' => WP01_Content::get_image_src('icons/4/append-link-on-copy_m.jpg'),
        'path' => 'append-link-on-copy/index.php',
        'analogs' =>  array(
            array(
                'name' => 'CopyLink',
                'icon' => WP01_Content::get_image_src('icons/4/copy-link_s.jpg'),
                'path' => 'copy-link/wp-copy.php',
                'settings_link'  => '/admin.php?page=copy-link%2Fadmin%2Fcopied.php',
            ),
            array(
                'name' => 'WP Copy Content Protection',
                'icon' => WP01_Content::get_image_src('icons/4/wp-copy-content-protection_s.jpg'),
                'path' => 'wp-copy-content-protection/wp-copy-content-protection.php',
                'settings_link'  => '/options-general.php?page=wccp_copy_protection',
            ),
            array(
                'name' => 'Add Link to Copied Text',
                'icon' => WP01_Content::get_image_src('icons/4/add-link-to-copied-text_s.jpg'),
                'path' => 'add-link-to-copied-text/settings.php',
                'settings_link'  => '/options-general.php?page=ftAddlink_options',
            )
        ),
        'desc' => 'Substitutes a link to the source page when copying the text',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=append_link_on_copy_options',
		'replace_level' => 'Полная',
		'code_replace' => '
<strong>Ссылка на первоисточник при копировании контента:</strong><br>
1. Откройте файл footer.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">LuckyWP Scripts Control</a> (Шаг 6)<br>
2. Добавьте до тега &lt;/body&gt; код:<br>
<div class="tc">
	/* WP01: Ссылка на первоисточник при копировании */<br>
	&lt;script type=&quot;text/javascript&quot;&gt;<br>
	//&lt;![CDATA[<br>
	function addLink() {<br>
	var body_element = document.getElementsByTagName(&#039;body&#039;)[0];<br>
	var selection = window.getSelection();<br>
	var pagelink = &quot;&lt;p&gt;Первоисточник: &lt;a href=&#039;&quot;+document.location.href+&quot;&#039;&gt;&quot;+document.location.href+&quot;&lt;/a&gt;&lt;/p&gt;&quot;;<br>
	var copytext = selection + pagelink;<br>
	var newdiv = document.createElement(&#039;div&#039;);<br>
	newdiv.style.position = &#039;absolute&#039;;<br>
	newdiv.style.left = &#039;-99999px&#039;;<br>
	body_element.appendChild(newdiv);<br>
	newdiv.innerHTML = copytext;<br>
	selection.selectAllChildren(newdiv);<br>
	window.setTimeout( function() {<br>
	body_element.removeChild(newdiv);<br>
	   }, 0);<br>
	}<br>
	document.oncopy = addLink;<br>
	//]]&gt;<br>
	&lt;/script&gt;<br><br>
</div>
<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'name' => 'Safe SVG',
        'icon' => WP01_Content::get_image_src('icons/4/safe-svg_m.jpg'),
        'path' => 'safe-svg/safe-svg.php',
        'analogs' =>  array(
            array(
                'name' => 'SVG Support',
                'icon' => WP01_Content::get_image_src('icons/4/svg-support_s.jpg'),
                'path' => 'svg-support/svg-support.php',
                'settings_link'  => '/options-general.php?page=svg-support',
            ),
            array(
                'name' => 'Lord of the Files: Enhanced Upload Security',
                'icon' => WP01_Content::get_image_src('icons/4/blob-mimes_s.jpg'),
                'path' => 'blob-mimes/index.php',
                'settings_link'  => '/options-general.php?page=blob-mimes-settings',
            )
        ),
        'desc' => 'Support SVG + sanitizer, ability to upload SVG only to administrators.<br> <strong>Reason:</strong> SVG files allow embedding JavaScript that can be used for XSS attacks. <strong>Online SVG sanitizer:</strong> <a href="http://svg.enshrined.co.uk" target="_blank">http://svg.enshrined.co.uk</a>',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '',
    ),
    array(
        'name' => 'Anti-Malware Security and Brute-Force Firewall',
        'icon' => WP01_Content::get_image_src('icons/4/gotmls_m.jpg'),
        'path' => 'gotmls/index.php',
        'desc' => 'Signature-based antivirus solution',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/admin.php?page=GOTMLS-settings',
    ),
    array(
        'name' => 'The Hack Repair Guy&#039;s Admin Login Notifier',
        'icon' => WP01_Content::get_image_src('icons/4/the-hack-repair-guys-admin-login-notifier_m.jpg'),
        'path' => 'the-hack-repair-guys-admin-login-notifier/the-hack-repair-guys-admin-login-notifier.php',
        'desc' => 'Email notification of administrator login (there is a list of ip exceptions)',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Preparing texts...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-general.php?page=hackrepair-admin-login-notifier-settings',
    ),
    array(
        'name' => 'Kama SpamBlock',
        'icon' => WP01_Content::get_image_src('icons/4/kama-spamblock_m.jpg'),
        'path' => 'kama-spamblock/kama-spamblock.php',
        'desc' => 'Protection of comments from spam by checking for clicking the "submit comment" button (submit)',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'to config',
        'settings_link'  => '/options-discussion.php#wpfooter',
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

<h4>1. Check for unique keys and authentication salts</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Check the code</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Follow the steps:</strong><br>
1. In the file "wp-config.php " find 8 lines with <code>define(&#039;AUTH_KEY&#039;</code> by <code>define(&#039;NONCE_SALT&#039;</code><br>
2. If the phrases next to them are not filled in (empty lines) - fix it immediately!<br>
<br>
<strong>Note:</strong><br>
You can write random code manually or use the official WordPress generator: <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank">https://api.wordpress.org/secret-key/1.1/salt/</a>
<br>
    </div>
</div>

<h4>2. Update the CMS, theme, plugins, and translations</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow the recommendations</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
- Be sure to <a href="/wp-admin/admin.php?page=wp01#step-2" target="_blank">create a backup</a> of FTP files and MySQL database before performing any updates!<br>
- Check with your hosting provider for backups and the ability to restore them instantly.<br>
- Edits and manual code settings in CMS files/plugins/themes will be destroyed during the update.<br>
- Outdated plugins may not support the current version of WordPress.<br>
- Check out the minimum and recommended <a href="https://wordpress.org/about/requirements/" target="_blank">requirements</a> for working with WordPress.<br>
<br>
<strong>Recommendations:</strong><br>
Go to the "<a href="/wp-admin/index.php" target="_blank">Dashboard</a> -> "<a href="/wp-admin/update-core.php" target="_blank">Updates</a>" section and perform the following actions:<br>
&nbsp; 1. Click "Update now" to update WordPress To the latest version.<br>
&nbsp; 2. Select the plugins in the "Plugins" section that you want to update and click "Update plugins".<br>
&nbsp; 3. Select the themes in the "Themes" section that you want to update and click "Update themes".<br>
&nbsp; 4. Click "Update transfers" in the "Transfers" section.<br>

<br>
<strong>Reference:</strong><br>
Outdated plugins may contain critical gaps, read more: <a href="https://blog.sucuri.net/tag/wordpress-plugins-and-themes" target="_blank">https://blog.sucuri.net</a><br>
WordPress releases contain multiple bug fixes, security improvements, and more: <a href="https://wordpress.org/news/category/releases/" target="_blank">CMS version history</a><br>
Information on fixed vulnerabilities in Wordpress versions: <a href="https://wordpress.org/news/category/security/" target="_blank">https://wordpress.org/news/category/security/</a>
<br>
    </div>
</div>

<h4>3. Check the origin of the theme and plugins</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow the recommendations</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Installed themes, plugins, and their nulled (hacked) versions may contain viruses, shells, and backdoors that are not installed from the official repository.<br>
Use only trusted web-based products!<br>
<br>
<strong>Recommendations:</strong><br>
Perform a revision of the plugins and the active theme.<br>
If you have doubts about the source of their receipt, reinstall using the WordPress repository: <a href="https://ru.wordpress.org/themes/" target="_blank">themes</a>, <a href="https://ru.wordpress.org/plugins/" target="_blank">plugins</a><br>
<br>
<strong>Reference:</strong><br>
WordPress is the most infected (according to the data "<a href="https://sucuri.net" target="_blank">SUCURI</a>") CMS system.<br>
Percentage of infected Wordpress detected: in 2018 - <a href="https://sucuri.net/reports/19-sucuri-2018-hacked-report.pdf" target="_blank">90%</a>, in 2019 - <a href="https://sucuri.net/wp-content/uploads/2020/01/20-sucuri-2019-hacked-report-1.pdf" target="_blank">94%</a>
<br>
    </div>
</div>

<h4>4. Prohibit offline browsers from downloading the site</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Add robots.txt instructions</div>
    <div class="collapse-body" style="display: none;">
<pre>
User-agent: Aqua_Products
Disallow: /
User-agent: asterias
Disallow: /
User-agent: b2w/0.1
Disallow: /
User-agent: BackDoorBot/1.0
Disallow: /
User-agent: Black Hole
Disallow: /
User-agent: BlowFish/1.0
Disallow: /
User-agent: Bookmark search tool
Disallow: /
User-agent: BotALot
Disallow: /
User-agent: BuiltBotTough
Disallow: /
User-agent: Bullseye/1.0
Disallow: /
User-agent: BunnySlippers
Disallow: /
User-agent: Cegbfeieh
Disallow: /
User-agent: CheeseBot
Disallow: /
User-agent: CherryPicker
Disallow: /
User-agent: CherryPicker /1.0
Disallow: /
User-agent: CherryPickerElite/1.0
Disallow: /
User-agent: CherryPickerSE/1.0
Disallow: /
User-agent: CopyRightCheck
Disallow: /
User-agent: cosmos
Disallow: /
User-agent: Crescent
Disallow: /
User-agent: Crescent Internet ToolPak HTTP OLE Control v.1.0
Disallow: /
User-agent: DittoSpyder
Disallow: /
User-agent: EmailCollector
Disallow: /
User-agent: EmailSiphon
Disallow: /
User-agent: EmailWolf
Disallow: /
User-agent: EroCrawler
Disallow: /
User-agent: ExtractorPro
Disallow: /
User-agent: FairAd Client
Disallow: /
User-agent: Flaming AttackBot
Disallow: /
User-agent: Foobot
Disallow: /
User-agent: Gaisbot
Disallow: /
User-agent: GetRight/4.2
Disallow: /
User-agent: grub
Disallow: /
User-agent: grub-client
Disallow: /
User-agent: Harvest/1.5
Disallow: /
User-agent: hloader
Disallow: /
User-agent: httplib
Disallow: /
User-agent: humanlinks
Disallow: /
User-agent: InfoNaviRobot
Disallow: /
User-agent: Iron33/1.0.2
Disallow: /
User-agent: JennyBot
Disallow: /
User-agent: Kenjin Spider
Disallow: /
User-agent: Kenjin Spider
Disallow: /
User-agent: Keyword Density/0.9
Disallow: /
User-agent: larbin
Disallow: /
User-agent: LexiBot
Disallow: /
User-agent: libWeb/clsHTTP
Disallow: /
User-agent: LinkextractorPro
Disallow: /
User-agent: LinkScan/8.1a Unix
Disallow: /
User-agent: LinkWalker
Disallow: /
User-agent: LNSpiderguy
Disallow: /
User-agent: lwp-trivial
Disallow: /
User-agent: lwp-trivial/1.34
Disallow: /
User-agent: Mata Hari
Disallow: /
User-agent: Microsoft URL Control
Disallow: /
User-agent: Microsoft URL Control - 5.01.4511
Disallow: /
User-agent: Microsoft URL Control - 6.00.8169
Disallow: /
User-agent: MIIxpc
Disallow: /
User-agent: MIIxpc/4.2
Disallow: /
User-agent: Mister PiX
Disallow: /
User-agent: moget
Disallow: /
User-agent: moget/2.1
Disallow: /
User-agent: Mozilla/4.0 (compatible; BullsEye; Windows 95)
Disallow: /
User-agent: MSIECrawler
Disallow: /
User-agent: NetAnts
Disallow: /
User-agent: NetMechanic
Disallow: /
User-agent: NICErsPRO
Disallow: /
User-agent: Offline Explorer
Disallow: /
User-agent: Openbot
Disallow: /
User-agent: Openfind
Disallow: /
User-agent: Openfind data gathere
Disallow: /
User-agent: Oracle Ultra Search
Disallow: /
User-agent: PerMan
Disallow: /
User-agent: ProPowerBot/2.14
Disallow: /
User-agent: ProWebWalker
Disallow: /
User-agent: Python-urllib
Disallow: /
User-agent: QueryN Metasearch
Disallow: /
User-agent: Radiation Retriever 1.1
Disallow: /
User-agent: RepoMonkey
Disallow: /
User-agent: RepoMonkey Bait & Tackle/v1.01
Disallow: /
User-agent: RMA
Disallow: /
User-agent: searchpreview
Disallow: /
User-agent: SiteSnagger
Disallow: /
User-agent: SpankBot
Disallow: /
User-agent: spanner
Disallow: /
User-agent: suzuran
Disallow: /
User-agent: Szukacz/1.4
Disallow: /
User-agent: Teleport
Disallow: /
User-agent: TeleportPro
Disallow: /
User-agent: Telesoft
Disallow: /
User-agent: The Intraformant
Disallow: /
User-agent: TheNomad
Disallow: /
User-agent: TightTwatBot
Disallow: /
User-agent: Titan
Disallow: /
User-agent: toCrawl/UrlDispatcher
Disallow: /
User-agent: True_Robot
Disallow: /
User-agent: True_Robot/1.0
Disallow: /
User-agent: turingos
Disallow: /
User-agent: URL Control
Disallow: /
User-agent: URL_Spider_Pro
Disallow: /
User-agent: URLy Warning
Disallow: /
User-agent: VCI
Disallow: /
User-agent: VCI WebViewer VCI WebViewer Win32
Disallow: /
User-agent: Web Image Collector
Disallow: /
User-agent: WebAuto
Disallow: /
User-agent: WebBandit
Disallow: /
User-agent: WebBandit/3.50
Disallow: /
User-agent: WebCopier
Disallow: /
User-agent: WebEnhancer
Disallow: /
User-agent: WebmasterWorldForumBot
Disallow: /
User-agent: WebSauger
Disallow: /
User-agent: Website Quester
Disallow: /
User-agent: Webster Pro
Disallow: /
User-agent: WebStripper
Disallow: /
User-agent: WebZip
Disallow: /
User-agent: WebZip/4.0
Disallow: /
User-agent: Wget
Disallow: /
User-agent: Wget/1.5.3
Disallow: /
User-agent: Wget/1.6
Disallow: /
User-agent: WWW-Collector-E
Disallow: /
User-agent: Zeus
Disallow: /
User-agent: Zeus 32297 Webster Pro V2.9 Win32
Disallow: /
User-agent: Zeus Link Scout
Disallow: /
</pre>
<br>
    </div>
</div>

<h4>5. Transfer wp-config.php to a higher level</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Read the instructions</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Make sure to create a backup of the file wp-config.php on your computer.<br>
DON't transfer IT wp-config.php to a folder at a higher level, if it is shared (for example, /www/wp01.ru/) for several sites, or if it already contains this file.<br>
<br>
<strong>Instruction manual:</strong><br>
&nbsp; 1. Connect to the FTP server (or use the file Manager in the hosting control panel), go to the folder with your site's files.<br>
&nbsp; 2. Create a backup of the file wp-config.php on your computer.<br>
&nbsp; 3. Move wp-config.php to a higher-level folder (for example, from /home/www/wp01.ru/html/ to /home/www/wp01.ru/).<br>
<br>
<strong>Reference:</strong><br>
File wp-config.php in a folder level higher, the root is not available from the Internet, but is visible for WordPress
<br>
    </div>
</div>

<h4>6. Use tamper-proof passwords</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow the recommendations</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Before editing a file wp-config.php carefully review the procedure for changing The MySQL password from your hosting provider.<br>
After changing the password for MySQL, the site will not work until you enter the current one in the file wp-config.php<br>
<br>
<strong>Recommendations for changing the MySQL password:</strong><br>
&nbsp; 1. Create a backup of the file wp-config.php on your computer.<br>
&nbsp; 2. Change the password for the MySQL database.<br>
&nbsp; &nbsp; &nbsp; Create a complex password (from 25 characters using special characters, numbers, lowercase and uppercase English letters) yourself, or use the generator:<br>
&nbsp; &nbsp; &nbsp; <a href="https://my.norton.com/extspa/passwordmanager?path=pwd-gen" target="_blank">https://my.norton.com/extspa/passwordmanager</a><br>
&nbsp; &nbsp; &nbsp; <a href="https://www.expressvpn.com/ru/password-generator" target="_blank">https://www.expressvpn.com/ru/password-generator</a><br>
&nbsp; 3. Change in the file wp-config.php for <code>define (&#039;DB_PASSWORD&#039;, &#039;current_parole&#039;);</code> value "current_parole"<br>
<br>
<strong>Recommendations for changing the site administrator password:</strong><br>
&nbsp; 1. in the admin panel, select "<a href="/wp-admin/users.php" target="_blank">Users</a>" -> "<a href="/wp-admin/profile.php" target="_blank">Profile</a>" and in the "account Management" section, click "Create password".<br>
&nbsp; 2. the System will generate a password - leave it, or enter your own.<br>
&nbsp; &nbsp; &nbsp; Use a complex password (at least 25 characters with special characters, numbers, lowercase and uppercase English letters). Online generators:<br>
&nbsp; &nbsp; &nbsp; <a href="https://my.norton.com/extspa/passwordmanager?path=pwd-gen" target="_blank">https://my.norton.com/extspa/passwordmanager</a><br>
&nbsp; &nbsp; &nbsp; <a href="https://www.expressvpn.com/ru/password-generator" target="_blank">https://www.expressvpn.com/ru/password-generator</a><br>
&nbsp; 3. Save your password for future use and click "Update profile" to save the change.
<br><br>
<strong>Reference:</strong><br>
You can check the password in the database among the previously detected data leaks on the page <a href="https://haveibeenpwned.com/Passwords" target="_blank">https://haveibeenpwned.com/Passwords</a>
<br>
    </div>
</div>

<h4>7. Remove unused plugins/themes</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow the recommendations</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Make sure to create a backup of the deleted items<br>
<br>
<strong>Recommendations for deleting unused themes:</strong><br>
&nbsp; 1. in the admin panel, go to "<a href="/wp-admin/themes.php" target="_blank">Appearance</a>" -> "<a href="/wp-admin/themes.php" target="_blank">Themes</a>"<br>
&nbsp; 2. Delete unused themes<br>
<br>
<strong>Recommendations for removing unused plugins:</strong><br>
&nbsp; 1. in the admin panel, go to "<a href="/wp-admin/plugins.php" target="_blank">Plugins</a>" -> "<a href="/wp-admin/plugins.php" target="_blank">Installed Plugins</a>"<br>
&nbsp; 2. Select " Inactive (x)" to display deactivated plugins<br>
&nbsp; 3. Remove unnecessary plugins<br>
<br>
<strong>Reference:</strong><br>
Unused themes/plugins not only take up disk space, but may also have vulnerabilities in the code
<br>
    </div>
</div>

<h4>8. Switch to the developer-supported PHP version</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow the recommendations</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Attention!</font></strong><br>
Very often, switching to a more recent version of PHP causes errors in plugins, themes, and/or CMS.<br>
We recommend changing the PHP version directly by the programmer.<br>
Official WordPress recommendations: <a href="https://wordpress.org/support/update-php/" target="_blank">https://wordpress.org/support/update-php/</a><br>
<br>
<strong>Confirmed support:</strong><br>
WordPress 5.2: PHP 5.6.20-7.3<br>
WordPress 5.3: PHP 5.6.20-7.4<br>
<br>
<strong>Algorithm for changing the PHP version:</strong><br>
&nbsp; 1. Check the compatibility of themes and plugins with a more recent version of PHP using the "<a href="https://ru.wordpress.org/plugins/php-compatibility-checker/" target="_blank">PHP Compatibility Checker</a>"<br>
&nbsp; 2. Go to your hosting control panel (for example, ISPmanager)<br>
&nbsp; 3. In the site settings, gradually increase the PHP version (for example, 5.4 -> 5.5 -> 5.6 -> 7.0), simultaneously testing the project for errors<br>
&nbsp; 4. If errors appear on the site when activating a more recent version of PHP, return the version to the previously used one. if necessary, contact the hosting technical support<br>
<br>
<strong>Reference:</strong><br>
The released version of PHP is supported for 3 years, after which it may contain critical errors/problems, read more: <a href="https://www.php.net/supported-versions.php" target="_blank">https://www.php.net/supported-versions.php</a><br>
Currently the most supported WordPress system is PHP version 7.4
<br>
    </div>
</div>

<h4>9. Check the site files with a cloud-based antivirus</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Implement an antivirus solution</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Site connection algorithm:</strong><br>
&nbsp; 1. Register on the service <a href="https://virusdie.com/" target="_blank">https://virusdie.com</a><br>
&nbsp; 2. Add your site (you will need to host the file) to the list of checks<br>
&nbsp; 3. Run the scanner, which will display the infected files (if any)<br>
&nbsp; 4. Study the result manually and take measures to remove infections<br>
<br>
<strong>Note:</strong><br>
False positives of the antivirus are possible.<br>
The free version allows you to scan 1 site.<br>
Automatic treatment is only possible with the purchase of an expensive license.
<br>
    </div>
</div>

<h4>10. Check for leaks (according to data from the darknet) sites by email</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Perform the check</div>
    <div class="collapse-body" style="display: none;">
<br>
As a result of hacking sites or infecting computers with viruses, confidential data from accounts that fall into the  <a href="https://ru.wikipedia.org/wiki/Даркнет" target="_blank">darknet</a> is disclosed. 
In turn, almost every account on the network contains an email-as a login, a means to restore access, or a method of confirming registration.
Search the database of known leaks and, if you find any disclosures, take measures to change passwords.
<br><br>
<strong>Verification algorithm::</strong><br>
&nbsp; 1. Go to Projects <a href="https://haveibeenpwned.com/" target="_blank">https://haveibeenpwned.com/</a> и <a href="https://monitor.firefox.com/" target="_blank">https://monitor.firefox.com/</a><br>
&nbsp; 2. Enter all the email addresses you use one by one and perform a search<br>
&nbsp; 3. Analyze the results<br>
&nbsp; 4. Update the password for all found disclosures<br>
&nbsp; 5. Perform periodic checks to identify new leaks<br>
<br>
<strong>Recommendations:</strong><br>
&#10003; When saving passwords in the browser, activate the master password<br>
&#10003; The use of a password manager helps to solve some of the security problems. We recommend a commercial product: <a href="https://www.kaspersky.ru/password-manager" target="_blank">Kaspersky Password Manager</a><br>
&#10003; <a href="https://browser.yandex.ru/" target="_blank">Yandex Browser</a> is equipped with the "Protect" protection technology and is the most secure for web surfing<br>
&#10003; Common practice: write passwords to a text file that is archived using a password<br>
&#10003; The relevance of the operating system, the availability of antivirus software and the rejection of hacked (pirated) programs-the basis of security
<br>
    </div>
</div>

<h4>11. Reduce the load on the site</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Write down the restrictions</div>
    <div class="collapse-body" style="display: none;">
<br>
The ban on the ip of countries and search engines is useful if:<br>
- the site has a high traffic from countries for which no content is provided;<br>
- crawlers of search engines that are not interesting to you are very active on the site;<br>
- there are signs of a DDoS attack.
<br><br>
<strong>The algorithm:</strong><br>
&nbsp; 1. Go to the page for generating restrictions/permissions for <a href="https://www.ip2location.com/free/visitor-blocker" target="_blank">visitors by country</a> or <a href="https://www.ip2location.com/free/robot-whitelist" target="_blank">search engine crawlers</a><br>
&nbsp; 2. Select the filter conditions (Country/Search Engine) and the work format (Output Format)<br>
&nbsp; 3. Download the file with the rules using the "Download" button"<br>
&nbsp; 4. Enter in .htaccess file located in the root of your site, the corresponding rules<br>
<br>
    </div>
</div>

<h4>12. Check the site for hidden administrators</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Perform the check</div>
    <div class="collapse-body" style="display: none;">
<br>
In the case of hacking, or when treating a previously infected site, hidden administrators may appear. Identification and removal of such users is possible only by means of phpMyAdmin.
<br><br>
<strong>The algorithm:</strong><br>
&nbsp; 1. Go to the section "<a href="/wp-admin/users.php?role=administrator" target="_blank">Users -> Administrator</a>"<br>
&nbsp; 2. Compare the number next to "Administrator (<font color= "red">X</font>) " with the number of users in this section, if the value does not match, follow these steps:<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.1. Log in to phpMyAdmin<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.2. Open the "wp_users" table and remember the "ID" value for the administrators you know<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.3. Open the " SQL " tab and run the query:<br>
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; <code>select * from <font color="red">wp_usermeta</font> where meta_value LIKE &#039;%administrator%&#039;;</code><br>
&nbsp; &nbsp; &nbsp; &nbsp; The block will display all users with administrator rights<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.4. Delete all values for the "user_id" column that were not in the "wp_users" table"<br>
&nbsp; 3. Check that the numbers in the "Users -> Administrator" section match the actual number of administrators<br>
<br>
    </div>
</div>

<h4>13. Create a user for publishing articles</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Follow these steps</div>
    <div class="collapse-body" style="display: none;">
<br>
By using an administrator account to publish articles on the site, you simplify the detection and subsequent hacking of a user with unlimited rights.
It is a good practice to embed a user with "Author" or "Editor" rights.
<br><br>
<strong>The algorithm:</strong><br>
&nbsp; 1. Go to the section "<a href="/wp-admin/user-new.php" target="_blank">Users -> Add New User</a>"<br>
&nbsp; 2. Create a new user by specifying <a href="https://ru.wordpress.org/support/article/roles-and-capabilities/" target="_blank">the role</a> "Author" or " Editor"<br>
&nbsp; 3. Log out of the administrator and log in with a new account<br>
&nbsp; 4. Log in to the administrator account only for actions that the author/editor's restrictions do not allow (for example, updating CMS/plugins)<br>
<br>
    </div>
</div>
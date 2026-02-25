<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Подсказка</h3>

    <p>1. Защиту сайта рекомендуем начать с обновления CMS/плагинов/темы.
        <br>Большинство скрытых брешей кроется именно в устаревшем коде.</p>
    <p>2. Часть защит, при неправильном их использовании, могут заблокировать 
		<br>элементы (например, YouTube видео), привести к брешу, или
		<br>к неправильной работе сайта. Рекомендуем осуществлять детальную 
		<br>проверку контента и функциональной части после каждого внедрения.</p>
	<p>3. При возникновении сложностей в установке кода, либо появлении 
		<br>непредвиденных ошибок, обращайтесь в техподдержку хостера, детально
		<br>описав что вы делаете, для чего и что именно не получается.
		<br>В большинстве случаев вам помогут или подскажут верное решение.
		<br>Если на вопросы вы получаете лишь стандартную отписку вида
		<br>"не в нашей компетенции" или "обратитесь к разработчику сайта" - 
		<br>рассмотрите другого хостинг провайдера, например <a href="https://www.reg.ru/hosting/?rlink=reflink-6247477" target="_blank">reg.ru</a></p>
    <p>4. Все плагины устанавливаются в папку /wp-content/plugins/ поэтому,
        <br>если после активации, сайт выдаст ошибку (белый экран), то просто
        <br>зайдите на FTP и деактивируйте конфликтный плагин, подставив в название
        <br>его папки цифру/букву. Для возобновления его работы зайдите в админ панель
        <br>сайта и нажмите "Активировать" рядом с плагином.</p>
</div>

<h2>Шаг 4/7. <span class="name">Защита от спама и взлома</span></h2>

<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Важно:</strong><br>
        Без изучения кода сайта/плагинов/темы можно определить лишь явные ошибки в защите. Рекомендуем устранить максимальное количество как выявленных
		брешей/замечаний, так и установить блокираторы/файрволлы/сканеры для пресечения возможных воздействий на ваш проект со стороны.  
		Начните работу по защите с изучения HTTP заголовков и сканирования Frontend части сайта на вирусы.
	</p>
</div>

<table class="widefat table-not-full-width plugins">
    <thead>
    <tr>
        <th style="width:100px">Сервис</th>
        <th>Назначение</th>
		<th>Язык</th>
        <th>Рекомендации</th>
    </tr>
    </thead>
    <tbody>
    <tr class="inactive">
        <td><a href="https://securityheaders.com/" target="_blank">Security Headers</a></td>
        <td>Анализатор HTTP заголовков с их отображением и комментариями.
        </td>
		<td>ENG
		</td>
        <td>Стремитесь исправить все замечания
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://seolik.ru/security-headers" target="_blank">SeoLik</a></td>
        <td>Тестирование основных HTTP заголовков сайта, которые влияют на уровень защиты, от различных интернет-атак.
        </td>
		<td>RUS
		</td>
        <td>Стремитесь исправить все замечания
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://www.virustotal.com" target="_blank">VirusTotal</a></td>
        <td>Сканирование файлов/URL/IP по базе 83 offline/online антивирусов.<br><strong>Основные сканеры:</strong> <a href="https://yandex.ru/safety/" target="_blank">Yandex Safe Browsing</a> (<a href="https://yandex.ru/support/search/beware/harmful-sites.html" target="_blank">справка</a>) и <a href="https://transparencyreport.google.com/safe-browsing/search" target="_blank">Google Safe Browsing</a> (<a href="https://safebrowsing.google.com/" target="_blank">справка</a>)
        </td>
		<td>ENG
		</td>
        <td>Позаботьтесь об отсутствии на сайте вирусов
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://encoder.till.im/scanner" target="_blank">Email scanner</a></td>
        <td>Сканер защищённости Email адресов от спама на странице сайта.<br><strong>Ручной декодер:</strong> <a href="http://www.wbwip.com/wbw/emailencoder.html" target="_blank">http://www.wbwip.com/wbw/emailencoder.html</a>
        </td>
		<td>ENG
		</td>
        <td>Защитите Email адреса от спама
        </td>
    </tr>
	<tr class="inactive">
        <td><a href="https://www.mail-tester.com/" target="_blank">Mail Tester</a></td>
        <td>Тестирование получения писем сторонним пользователем с рядом проверок на подлинность<br><strong>Рекомендуем:</strong> <a href="https://mxtoolbox.com/blacklists.aspx" target="_blank">проверка ip сайта в 100+ blacklists</a>, а также <a href="https://2ip.ru/lookup/" target="_blank">определение ip сайта</a>
        </td>
		<td>RUS
		</td>
        <td>Исправьте ошибки и исключите из спамлистов
        </td>
    </tr>
    </tbody>
</table>

<h3>I. Плагины для ускорения</h3>
<p>Установите плагины соответствующие необходимым задачам</p>

<?php

$titles = array('Плагин', 'Статус', 'Аналоги', 'Замена кодом', 'Задача', 'Важность модуля', 'Управление', 'Инструкция по настройке');
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
        'desc' => 'Внедряет Google reCAPTCHA на подверженные спаму/взлому страницы',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Настраиваемая всесторонняя защита от всех основых угроз',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Позволяет заблокировать правую кнопку мыши и внедрить некоторые защиты от копирования',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Отключение не нужных тегов/ссылок/данных в head блоке',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Хорошая блокировка спама',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://antispambee.pluginkollektiv.org/documentation/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://antispambee.pluginkollektiv.org/documentation/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://antispambee.pluginkollektiv.org/documentation/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Защита HTTP заголовков',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация от Mozilla:<br> 
<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://developer.mozilla.org/ru/docs/Web/HTTP/Заголовки" target = "_blank"><strong>RUS</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" target = "_blank"><strong>RUS(GT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=http-headers',
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
        'desc' => 'Защита Email адресов от спам ботов путем кодирования кода',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, поместите email в шорткод: <br>[nospam] [/nospam]',
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
        'desc' => 'Защита от спама, которая позволяет не использовать капчу, уменьшает нагрузку на хостинг.',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'link' => '<a href="https://cleantalk.org/ru/?pid=255609" class="button button-green" target = "_blank">Зарегистрироваться</a><br>'.
                  'Необходима покупка лицензии, есть тестовый период + бонусы.',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Подставляет при копировании текста ссылку на страницу-первоисточник',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
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
        'desc' => 'Поддержка SVG + санитайзер, возможность загрузки SVG только администраторам.<br> <strong>Причина:</strong> SVG файлы позволяют встраивать JavaScript, который может быть использован для XSS атак. <strong>Online SVG санитайзер:</strong> <a href="http://svg.enshrined.co.uk" target="_blank">http://svg.enshrined.co.uk</a>',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен',
        'settings_link'  => '',
    ),
    array(
        'name' => 'Anti-Malware Security and Brute-Force Firewall',
        'icon' => WP01_Content::get_image_src('icons/4/gotmls_m.jpg'),
        'path' => 'gotmls/index.php',
        'desc' => 'Сигнатурное антивирусное решение',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/admin.php?page=GOTMLS-settings',
    ),
    array(
        'name' => 'The Hack Repair Guy&#039;s Admin Login Notifier',
        'icon' => WP01_Content::get_image_src('icons/4/the-hack-repair-guys-admin-login-notifier_m.jpg'),
        'path' => 'the-hack-repair-guys-admin-login-notifier/the-hack-repair-guys-admin-login-notifier.php',
        'desc' => 'Email уведомление о входе администратора в систему (есть список ip исключений)',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=hackrepair-admin-login-notifier-settings',
    ),
    array(
        'name' => 'Kama SpamBlock',
        'icon' => WP01_Content::get_image_src('icons/4/kama-spamblock_m.jpg'),
        'path' => 'kama-spamblock/kama-spamblock.php',
        'desc' => 'Защита комментариев от спама методом проверки на предмет нажатия кнопки "отправить комментарий" (submit)',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-discussion.php#wpfooter',
    )
);

WP01_Table::the_table($titles, $plugins);

?>

<h3>II. Быстрый бэкап</h3>
<p>Перед ручными внедрениями кода настоятельно рекомендуем сделать резервную копию файлов, которые будут редактироваться</p>

<?php 
/* start new */
$titles = array('Название', 'Расположение', 'Назначение', 'Управление');
    
        $structure = array(
/*          array(
                "filename" => '.htaccess',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'Файл дополнительной конфигурации веб-сервера',
                "button_text" => 'Скачать'
            ),
            array(
                "filename" => 'wp-config.php',
                "path" => '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/',
                "comment" => 'Конфигурационный файл WordPress',
                "button_text" => 'Скачать'
            ),
*/
            array(
                "filename" => 'footer.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Нижняя часть шаблона сайта',
                "button_text" => 'Скачать'
            ),
            array(
                "filename" => 'header.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Верхняя часть шаблона сайта',
                "button_text" => 'Скачать'
            ),
            array(
                "filename" => 'functions.php',
                "path" => '/wp-content/themes/'. get_template() . '/',
                'fullPath' => $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/'. get_template() . '/',
                "comment" => 'Файл темы с пользовательскими функциями',
                "button_text" => 'Скачать'
            )
        );

    WP01_Table::build_backup_table($titles, $structure); 
	/* end new */
?>

<h3>III. Ручные внедрения</h3>
<p>Произведите установку/правку кода в соответствии с необходимой задачей</p>

<h4>1. Проверьте наличие уникальные ключей и солей для аутентификации</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Проверьте код</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Выполните действия:</strong><br>
1. В файле "wp-config.php" найдите 8 строчек с <code>define(&#039;AUTH_KEY&#039;</code> по <code>define(&#039;NONCE_SALT&#039;</code><br>
2. Если фразы рядом с ними не заполнены (пустые строчки) - срочно исправьте это!<br>
<br>
<strong>Примечание:</strong><br>
Можете прописать случайный код как вручную, так и воспользоваться официальным WordPress генератором: <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank">https://api.wordpress.org/secret-key/1.1/salt/</a>
<br>
    </div>
</div>

<h4>2. Обновите CMS, тему, плагины, переводы</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните рекомендации</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
- Обязательно <a href="/wp-admin/admin.php?page=wp01#step-2" target="_blank">создайте бэкап</a> FTP файлов и MySQL базы перед выполнением любых обновлений!<br>
- Уточните у вашего хостинг-провайдера наличие бэкапов и возможность их моментального восстановления.<br>
- Правки и ручные простановки кода в файлах CMS/плагинах/теме при обновлении будут уничтожены.<br>
- Устаревшие плагины могут не поддерживать актуальную версию WordPress.<br>
- Ознакомьтесь с минимальными и рекомендуемыми <a href="https://ru.wordpress.org/about/requirements/" target="_blank">требованиями</a> для работы WordPress.<br>
<br>
<strong>Рекомендации:</strong><br>
Перейдите в раздел "<a href="/wp-admin/index.php" target="_blank">Консоль</a>" -> "<a href="/wp-admin/update-core.php" target="_blank">Обновления</a>" и произведите действия:<br>
&nbsp; 1. Нажмите "Обновить сейчас" для обновления WordPress до последней версии.<br>
&nbsp; 2. Выберите плагины в блоке "Плагины", которые вы хотите обновить, и нажмите "Обновить плагины".<br>
&nbsp; 3. Выберите темы в блоке "Темы", которые вы хотите обновить, и нажмите "Обновить темы".<br>
&nbsp; 4. Нажмите "Обновить переводы" в блоке "Переводы".<br>

<br>
<strong>Справка:</strong><br>
Устаревшие плагины могут содержать критические бреши, подробнее: <a href="https://blog.sucuri.net/tag/wordpress-plugins-and-themes" target="_blank">https://blog.sucuri.net</a> (ENG)<br>
Релизы WordPress содержат множественные исправления багов, улучшения защиты, подробнее: <a href="https://wordpress.org/news/category/releases/" target="_blank">история версий CMS</a> (ENG)<br>
Информация по исправленным уязвимостям в версиях Wordpress: <a href="https://wordpress.org/news/category/security/" target="_blank">https://wordpress.org/news/category/security/</a> (ENG)
<br>
    </div>
</div>

<h4>3. Проверьте происхождение темы и плагинов</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните рекомендации</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Установленные не с официального репозитория темы, плагины, а также их nulled (взломанные) версии могут содержать вирусы, шеллы, бэкдоры.<br>
Используйте только проверенные веб-продукты!<br>
<br>
<strong>Рекомендации:</strong><br>
Проведите ревизию плагинов и активной темы.<br>
При наличии сомнений в источнике их получения, переустановите, используя репозиторий WordPress: <a href="https://ru.wordpress.org/themes/" target="_blank">темы</a>, <a href="https://ru.wordpress.org/plugins/" target="_blank">плагины</a><br>
<br>
<strong>Справка:</strong><br>
WordPress является наиболее заражённой (по данным "<a href="https://sucuri.net" target="_blank">SUCURI</a>") CMS системой.<br>
Доля выявленных инфицированных Wordpress: в 2018 году - <a href="https://sucuri.net/reports/19-sucuri-2018-hacked-report.pdf" target="_blank">90%</a>, в 2019 году - <a href="https://sucuri.net/wp-content/uploads/2020/01/20-sucuri-2019-hacked-report-1.pdf" target="_blank">94%</a>
<br>
    </div>
</div>

<h4>4. Запретите скачивание сайта Offline браузерам</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Дополните robots.txt инструкциями</div>
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

<h4>5. Перенесите wp-config.php на уровень выше</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Изучите инструкцию</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Обязательно создайте бэкап файла wp-config.php на своём компьютере.<br>
НЕ ПЕРЕНОСИТЕ wp-config.php в папку на уровень выше, если она является общей (например, /www/wp01.ru/) для нескольких сайтов, или в ней уже присутствует данный файл.<br>
<br>
<strong>Инструкция:</strong><br>
&nbsp; 1. Подключитесь к FTP серверу (или воспользуйтесь менеджером файлов в панели управления хостинга), зайдите в папку с файлами вашего сайта.<br>
&nbsp; 2. Создайте бэкап файла wp-config.php на своём компьютере.<br>
&nbsp; 3. Переместите wp-config.php в папку на уровень выше (например, из папки /home/www/wp01.ru/html/ в папку /home/www/wp01.ru/).<br>
<br>
<strong>Справка:</strong><br>
Файл wp-config.php в папке на уровень выше корневой недоступен из Интернета, но виден для WordPress
<br>
    </div>
</div>

<h4>6. Используйте взломоустойчивые пароли</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните рекомендации</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Прежде чем редактировать файл wp-config.php внимательно изучите процедуру изменения пароля для MySQL у вашего хостинг-провайдера.<br>
После изменения пароля для MySQL сайт не будет работать, пока вы не пропишите актуальный в файле wp-config.php<br>
<br>
<strong>Рекомендации по изменению пароля к MySQL:</strong><br>
&nbsp; 1. Создайте бэкап файла wp-config.php на своём компьютере.<br>
&nbsp; 2. Измените пароль к базе данных MySQL.<br>
&nbsp; &nbsp; &nbsp; Создайте сложный пароль (от 25 символов используя спецсимволы, цифры, строчные и прописные английские буквы) самостоятельно, или воспользуйтесь генератором:<br>
&nbsp; &nbsp; &nbsp; <a href="https://my.norton.com/extspa/passwordmanager?path=pwd-gen" target="_blank">https://my.norton.com/extspa/passwordmanager</a><br>
&nbsp; &nbsp; &nbsp; <a href="https://www.expressvpn.com/ru/password-generator" target="_blank">https://www.expressvpn.com/ru/password-generator</a><br>
&nbsp; 3. Измените в файле wp-config.php для <code>define(&#039;DB_PASSWORD&#039;, &#039;текущий_пароль&#039;);</code> значение "текущий_пароль"<br>
<br>
<strong>Рекомендации по изменению пароля администратора сайта:</strong><br>
&nbsp; 1. В админ панели выберите "<a href="/wp-admin/users.php" target="_blank">Пользователи</a>" -> "<a href="/wp-admin/profile.php" target="_blank">Профиль</a>" и в разделе "Управление учётной записью" нажмите "Создать пароль".<br>
&nbsp; 2. Система сгенерирует пароль - оставьте его, или введите свой.<br>
&nbsp; &nbsp; &nbsp; Используйте сложный пароль (от 25 символов с спецсимволами, цифрами, строчными и прописными английскими буквами). Онлайн генераторы:<br>
&nbsp; &nbsp; &nbsp; <a href="https://my.norton.com/extspa/passwordmanager?path=pwd-gen" target="_blank">https://my.norton.com/extspa/passwordmanager</a><br>
&nbsp; &nbsp; &nbsp; <a href="https://www.expressvpn.com/ru/password-generator" target="_blank">https://www.expressvpn.com/ru/password-generator</a><br>
&nbsp; 3. Сохраните пароль для дальнейшего его использования и нажмите "Обновить профиль" для сохранения изменения.
<br><br>
<strong>Справка:</strong><br>
Проверить пароль в базе среди ранее обнаруженных при утечках данных можно на странице <a href="https://haveibeenpwned.com/Passwords" target="_blank">https://haveibeenpwned.com/Passwords</a>
<br>
    </div>
</div>

<h4>7. Удалите неиспользуемые плагины/темы</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните рекомендации</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Обязательно создайте бэкап удаляемых элементов<br>
<br>
<strong>Рекомендации по удалению неиспользуемых тем:</strong><br>
&nbsp; 1. В админ панели перейдите в раздел "<a href="/wp-admin/themes.php" target="_blank">Внешний вид</a>" -> "<a href="/wp-admin/themes.php" target="_blank">Темы</a>"<br>
&nbsp; 2. Удалите неиспользуемые темы<br>
<br>
<strong>Рекомендации по удалению неиспользуемых плагинов:</strong><br>
&nbsp; 1. В админ панели перейдите в раздел "<a href="/wp-admin/plugins.php" target="_blank">Плагины</a>" -> "<a href="/wp-admin/plugins.php" target="_blank">Установленные</a>"<br>
&nbsp; 2. Выберите "Неактивные (x)" для отображения деактивированных плагинов<br>
&nbsp; 3. Удалите ненужные плагины<br>
<br>
<strong>Справка:</strong><br>
Неиспользуемые темы/плагины не только занимают дисковое пространство, но и могут иметь уязвимости в коде
<br>
    </div>
</div>

<h4>8. Перейдите на поддерживаемую разработчиками PHP версию</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните рекомендации</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong><font color="red">Внимание!</font></strong><br>
Очень часто переход на более свежую версию PHP вызывает ошибки в работе плагинов, темы и/или CMS.<br>
Рекомендуем производить смену PHP версии непосредственно программистом.<br>
Официальные рекомендации WordPress: <a href="https://ru.wordpress.org/support/update-php/" target="_blank">https://ru.wordpress.org/support/update-php/</a><br>
<br>
<strong>Подтвержденная поддержка:</strong><br>
с WordPress 5.2: PHP 5.6.20-7.3<br>
с WordPress 5.3: PHP 5.6.20-7.4<br>
<br>
<strong>Алгоритм изменения версии PHP:</strong><br>
&nbsp; 1. Проверьте совместимость тем и плагинов с более свежей версией PHP с помощью "<a href="https://ru.wordpress.org/plugins/php-compatibility-checker/" target="_blank">PHP Compatibility Checker</a>"<br>
&nbsp; 2. Перейдите в панель управления вашим хостингом (например, ISPmanager)<br>
&nbsp; 3. В настройках сайта постепенно (например, 5.4 -> 5.5 -> 5.6 -> 7.0) увеличивайте версию PHP до максимально поддерживаемой (по данным "PHP Compatibility Checker"), параллельно тестируя проект на наличие ошибок<br>
&nbsp; 4. Если при активации более свежей версии PHP на сайте появляются ошибки - верните версию к ранее используемой, при необходимости обратитесь в техподдержку хостинга<br>
<br>
<strong>Справка:</strong><br>
Выпущенная версия PHP поддерживается в течение 3 лет, после чего может содержать критические ошибки/проблемы, подробнее: <a href="https://www.php.net/supported-versions.php" target="_blank">https://www.php.net/supported-versions.php</a> (ENG)<br>
На данный момент максимально поддерживаемая системой WordPress PHP версия 7.4
<br>
    </div>
</div>

<h4>9. Проверьте файлы сайта облачным антивирусом</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Внедрите антивирусное решение</div>
    <div class="collapse-body" style="display: none;">
<br>
<strong>Алгоритм подключения сайта:</strong><br>
&nbsp; 1. Зарегистрируйтесь на сервисе <a href="https://virusdie.com/" target="_blank">https://virusdie.com</a><br>
&nbsp; 2. Добавьте свой сайт (потребуется разместить файл на хостинге) в список проверок<br>
&nbsp; 3. Запустите сканер, по итогу которого будут отображены зараженные файлы (при их наличии)<br>
&nbsp; 4. Изучите вручную результат и примите меры для удаления заражений<br>
<br>
<strong>Примечание:</strong><br>
Возможны ложные срабатывания антивируса.<br>
Бесплатная версия позволяет осуществить сканирование 1 сайта.<br>
Автоматическое лечение возможно только при покупке дорогостоящей лицензии.
<br>
    </div>
</div>

<h4>10. Проверьте на утечки (по данным из даркнета) сайты по email</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните проверку</div>
    <div class="collapse-body" style="display: none;">
<br>
В результате взлома сайтов или заражения компьютеров вирусами раскрываются конфиденциальные данные из аккаунтов, которые попадают в <a href="https://ru.wikipedia.org/wiki/Даркнет" target="_blank">даркнет</a>. 
В свою очередь, почти каждый аккаунт в сети содержит email - как логин, средство для восстановления доступа, или метод подтверждения регистрации.
Осуществите поиск по базе известных утечек и, в случае нахождения раскрытий, примите меры по смене паролей.
<br><br>
<strong>Алгоритм проверки:</strong><br>
&nbsp; 1. Перейдите на проекты <a href="https://haveibeenpwned.com/" target="_blank">https://haveibeenpwned.com/</a> и <a href="https://monitor.firefox.com/" target="_blank">https://monitor.firefox.com/</a><br>
&nbsp; 2. Введите поочередно все используемые вами email и осуществите поиск<br>
&nbsp; 3. Проанализируйте результаты<br>
&nbsp; 4. Обновите пароль для всех найденных раскрытий<br>
&nbsp; 5. Осуществляйте периодические проверки для выявления новых утечек<br>
<br>
<strong>Советы:</strong><br>
&#10003; При сохранении паролей в браузере активируйте мастер-пароль<br>
&#10003; Применение менеджера паролей помогает решить часть задач безопасности. Рекомендуем коммерческий продукт: <a href="https://www.kaspersky.ru/password-manager" target="_blank">Kaspersky Password Manager</a><br>
&#10003; <a href="https://browser.yandex.ru/" target="_blank">Яндекс Браузер</a> снабжен технологией защиты "Protect" и является наиболее безопасным для веб серфинга<br>
&#10003; Частая практика: записывать пароли в текстовый файл, который заархивирован с применением пароля<br>
&#10003; Актуальность операционной системы, наличие антивируса и отказ от взломанных (пиратских) программ - основа безопасности
<br>
    </div>
</div>

<h4>11. Уменьшите нагрузку на сайт</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Пропишите ограничения</div>
    <div class="collapse-body" style="display: none;">
<br>
Запрет по ip стран и поисковых систем полезен в случае, если:<br>
- на сайте наблюдается высокая посещаемость из стран, для которых не предоставлен контент;<br>
- краулеры не интересных для вас поисковых систем проявляют высокую активность на сайте;<br>
- наблюдаются признаки DDoS атаки.
<br><br>
<strong>Алгоритм:</strong><br>
&nbsp; 1. Перейдите на страницу генерации ограничений/разрешений для <a href="https://www.ip2location.com/free/visitor-blocker" target="_blank">посетителей по странам</a> или <a href="https://www.ip2location.com/free/robot-whitelist" target="_blank">сканеров поисковых систем</a><br>
&nbsp; 2. Выберите условия фильтра (Country/Search Engine) и формат работы (Output Format)<br>
&nbsp; 3. Скачайте файл с правилами по кнопке "Download"<br>
&nbsp; 4. Внесите в .htaccess файл, находящийся в корне вашего сайта, соответствующие правила<br>
<br>
    </div>
</div>

<h4>12. Изучите сайт на наличие скрытых администраторов</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните проверку</div>
    <div class="collapse-body" style="display: none;">
<br>
В случае взлома, или при лечении ранее заражённого сайта, возможно появление скрытых администраторов. Выявление и удаление таких пользователей возможно только средствами phpMyAdmin.
<br><br>
<strong>Алгоритм:</strong><br>
&nbsp; 1. Перейдите в раздел "<a href="/wp-admin/users.php?role=administrator" target="_blank">Пользователи -> Администратор</a>"<br>
&nbsp; 2. Сравните цифру рядом с "Администратор (<font color="red">X</font>)" с количеством пользователей в данном разделе, если значение не совпадает - выполните действия:<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.1. Авторизуйтесь в phpMyAdmin<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.2. Откройте таблицу "wp_users" и запомните значение "ID" для известных вам администраторов<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.3. Откройте вкладку "SQL" и выполните запрос:<br>
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; <code>select * from <font color="red">wp_usermeta</font> where meta_value LIKE &#039;%administrator%&#039;;</code><br>
&nbsp; &nbsp; &nbsp; &nbsp; В блоке отобразятся все пользователи с правами администратора<br>
&nbsp; &nbsp; &nbsp; &nbsp; 2.4. Удалите все значения по столбцу "user_id", которых не было в таблице "wp_users"<br>
&nbsp; 3. Проверьте совпадение цифр в разделе "Пользователи -> Администратор" с реальным количеством администраторов<br>
<br>
    </div>
</div>

<h4>13. Создайте пользователя для публикации статей</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните действия</div>
    <div class="collapse-body" style="display: none;">
<br>
Используя учётную запись администратора для публикации статей на сайте вы упрощаете обнаружение и последующий взлом пользователя с неограниченными правами.
Хорошей практикой является внедрение пользователя с правами "Автор" или "Редактор".
<br><br>
<strong>Алгоритм:</strong><br>
&nbsp; 1. Перейдите в раздел "<a href="/wp-admin/user-new.php" target="_blank">Пользователи -> Добавить нового</a>"<br>
&nbsp; 2. Создайте нового пользователя указав <a href="https://ru.wordpress.org/support/article/roles-and-capabilities/" target="_blank">роль</a> "Автор" или "Редактор"<br>
&nbsp; 3. Выйдите из администратора и залогинетесь под новой учетной записью<br>
&nbsp; 4. Осуществляйте вход в учётную запись администратора только для действий выполнение которых не позволяют ограничения автора/редактора (например, обновление CMS/плагинов)<br>
<br>
    </div>
</div>
<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

?>
<div class="card tip">
    <h3>Подсказка</h3>

    <p>1. Все плагины устанавливаются в папку /wp-content/plugins/, поэтому,
        <br>если после активации сайт выдаст ошибку (белый экран), то просто
        <br>зайдите на FTP и деактивируйте конфликтный плагин, подставив
        <br>в название его папки цифру/букву. Для возобновления его работ
        <br>зайдите в админ панель сайта и нажмите "Активировать" рядом с плагином.</p>
    <p>2. Некоторые настройки плагинов могут конфликтовать с темой вашего сайта, 
		<br>или другими плагинами. Советуем активировать по очереди каждую функцию 
		<br>в плагинах и проверять работу сайта.</p>
    <p>3. Не забудьте в robots.txt поменять SAIT.RU на адрес вашего сайта.</p>
    <p>4. Если вы используете SSL сертификат на сайте, тогда инструкция "Host"
        <br>в файле robots.txt должна будет иметь вид Host: https://sait.ru</p>

</div>

<h2>Шаг 5/7. <span class="name">SEO оптимизация</span></h2>

<div class="notice notice-warning notice-alt inline">
    <p>
        <strong>Важно:</strong><br>
        Для понимания явных и скрытых недоработок, которые могут пагубно влиять на представление сайта в поисковых системах и занимаемые им позиции в результатах поиска, рекомендуем произвести анализ сайта. Хорошей практикой является присутствие проекта в вебмастерской Яндекса/Google и установленная метрика.
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
        <td><a href="https://be1.ru/stat/" target="_blank">BE1</a></td>
        <td>Анализ основных показателей и ошибок сайта<br><strong>Рекомендуем:</strong> <a href="https://wp01.ru/dopolnitelynye-nastroyki-sayta.php#p7" target="_blank">SEO анализ сайта по 30 показателям</a> (работа № 7)
        </td>
		<td>RUS
		</td>
        <td>Исключите ошибки, изучите SEO информацию
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://webmaster.yandex.ru/" target="_blank">Яндекс Вебмастер</a></td>
        <td>Анализ SEO показателей сайта и инструменты для работы с его представлением в поисковой системе Яндекс<br><strong>Рекомендуем:</strong> <a href="https://metrika.yandex.ru/" target="_blank">Яндекс Метрика</a>
        </td>
		<td>RUS
		</td>
        <td>Изучите данные сервиса
        </td>
    </tr>
    <tr class="inactive">
        <td><a href="https://www.google.ru/webmasters/" target="_blank">Google Вебмастер</a></td>
        <td>Изучение SEO данных сайта и сервис для работы с его отображением в Google<br><strong>Рекомендуем:</strong> <a href="https://analytics.google.com/analytics/" target="_blank">Google Аналитика</a>
        </td>
		<td>RUS
		</td>
        <td>Изучите данные сервиса
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
        'name' => '.PHP on PAGES',
        'icon' => WP01_Content::get_image_src('icons/5/php-on-pages_m.jpg'),
        'path' => 'php-to-pages/php-on-pages.php',
        'analogs' =>  array(
            array(
                'name' => 'Add Any Extension to Pages',
                'icon' => WP01_Content::get_image_src('icons/5/add-any-extension-to-pages_s.jpg'),
                'path' => 'add-any-extension-to-pages/add-any-extension-to-pages.php',
                'settings_link'  => '/options-general.php?page=add-any-extension-to-pages',
            ),
            array(
                'name' => 'Append extensions on Pages',
                'icon' => WP01_Content::get_image_src('icons/5/append-extensions-on-pages_s.jpg'),
                'path' => 'append-extensions-on-pages/append_extension_on_pages.php',
                'settings_link'  => '/admin.php?page=aeop_settings',
            )
        ),
        'desc' => 'Определяет расширение страниц как *.php<br><strong>Замечание:</strong> рекомендовано для новых и ещё не проиндексированных сайтов',
        'rate' => 1,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настройка не требуется',
        'settings_link'  => '',
    ),
    array(
        'name' => 'Cyrlitera – транслитерация ссылок и имен файлов',
        'icon' => WP01_Content::get_image_src('icons/5/cyrlitera_m.jpg'),
        'path' => 'cyrlitera/cyrlitera.php',
		'analogs' =>  array(
            array(
                'name' => 'Cyr-To-Lat',
                'icon' => WP01_Content::get_image_src('icons/5/cyr-to-lat_s.jpg'),
                'path' => 'cyr2lat/cyr-to-lat.php',
                'settings_link'  => '/options-general.php?page=cyr-to-lat',
            ),
            array(
                'name' => 'WP Translitera',
                'icon' => WP01_Content::get_image_src('icons/5/wp-translitera_s.jpg'),
                'path' => 'wp-translitera/wp-translitera.php',
                'settings_link'  => '/options-general.php?page=wp-translitera%2Fwp-translitera.php',
            ),
            array(
                'name' => 'Rus-To-Lat',
                'icon' => WP01_Content::get_image_src('icons/5/rus-to-lat_s.jpg'),
                'path' => 'rustolat/rus-to-lat.php',
                'settings_link'  => '/options-general.php?page=rustolat%2Frus-to-lat.php',
            )
        ),
        'desc' => 'Позволяет создавать URL страницы на латыни методом транслитерации',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=transliteration-wbcr_cyrlitera',
    ),
    array(
        'name' => 'Yoast SEO',
        'icon' => WP01_Content::get_image_src('icons/5/wordpress-seo_m.jpg'),
        'path' => 'wordpress-seo/wp-seo.php',
		'analogs' =>  array(
            array(
                'name' => 'All in One SEO Pack',
                'icon' => WP01_Content::get_image_src('icons/5/all-in-one-seo-pack_s.jpg'),
                'path' => 'all-in-one-seo-pack/all_in_one_seo_pack.php',
                'settings_link'  => '/admin.php?page=all-in-one-seo-pack%2Faioseop_class.php',
            ),
            array(
                'name' => 'The SEO Framework',
                'icon' => WP01_Content::get_image_src('icons/5/autodescription_s.jpg'),
                'path' => 'autodescription/autodescription.php',
                'settings_link'  => '/admin.php?page=theseoframework-settings',
            ),
            array(
                'name' => 'WordPress SEO Plugin — Rank Math',
                'icon' => WP01_Content::get_image_src('icons/5/seo-by-rank-math_s.jpg'),
                'path' => 'seo-by-rank-math/rank-math.php',
                'settings_link'  => '/admin.php?page=rank-math',
            )
        ),
        'desc' => 'Работа с мета-тегами и тонкая настройка SEO элементов',
        'rate' => 3,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://yoast.com/help/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://yoast.com/help/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://yoast.com/help/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/admin.php?page=wpseo_dashboard',
    ),
    array(
        'name' => 'Redirection',
        'icon' => WP01_Content::get_image_src('icons/5/redirection_m.jpg'),
        'path' => 'redirection/redirection.php',
		'analogs' =>  array(
            array(
                'name' => 'SEO Redirection Plugin — 301 Redirect Manager',
                'icon' => WP01_Content::get_image_src('icons/5/seo-redirection_s.jpg'),
                'path' => 'seo-redirection/seo-redirection.php',
                'settings_link'  => '/options-general.php?page=seo-redirection.php',
            ),
            array(
                'name' => '301 Redirects — Easy Redirect Manager',
                'icon' => WP01_Content::get_image_src('icons/5/eps-301-redirects_s.jpg'),
                'path' => 'eps-301-redirects/eps-301-redirects.php',
                'settings_link'  => '/options-general.php?page=eps_redirects',
            ),
            array(
                'name' => '301 Redirects',
                'icon' => WP01_Content::get_image_src('icons/5/301-redirects_s.jpg'),
                'path' => '301-redirects/301-redirects.php',
                'settings_link'  => '/options-general.php?page=301-redirects',
            )
        ),
        'desc' => 'Удобная работа с редиректами, определение 404 ошибок',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://redirection.me/support/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://redirection.me/support/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://redirection.me/support/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/tools.php?page=redirection.php&sub=options',
		'code_replace' => '
<strong>Замена функции &quot;301 переадресация&quot;:</strong><br>
1. Откройте файл .htaccess находящийся в корне сайта<br>
2. Добавьте код<br>
<div class="tc">
# WP01: 301 переадресация<br>
Options +FollowSymLinks<br>
RewriteEngine On<br>
Redirect 301 /old_link.php http://site.ru/new_link.php<br><br>
</div>

<strong>Примечание:</strong><br>
1. Значение &quot;/old_link.php&quot; нужно заменить на старую ссылку, с которой будет происходить редирект (писать всё, что после /)<br>
2. Значение &quot;http://site.ru/new_link.php&quot; нужно заменить на новую ссылку, на которую будет происходить редирект (URL адрес полностью)
		'
    ),
    array(
        'name' => 'Remove Category URL',
        'icon' => WP01_Content::get_image_src('icons/5/remove-category-url_m.jpg'),
        'path' => 'remove-category-url/remove-category-url.php',
		'analogs' =>  array(
            array(
                'name' => 'No Category Base (WPML)',
                'icon' => WP01_Content::get_image_src('icons/5/no-category-base-wpml_s.jpg'),
                'path' => 'no-category-base-wpml/no-category-base-wpml.php',
                'settings_link'  => '',
            ),
            array(
                'name' => 'Yoast SEO',
                'icon' => WP01_Content::get_image_src('icons/5/wp-seo_s.jpg'),
                'path' => 'wordpress-seo/wp-seo.php',
                'settings_link'  => '/admin.php?page=wpseo_dashboard',
            )
        ),
        'desc' => 'Убирает служебное "category" из URL структуры<br><strong>Замечание:</strong> рекомендовано для новых и ещё не проиндексированных сайтов',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настройка не требуется',
        'settings_link'  => '',
    ),
    array(
        'name' => 'Disable Feeds',
        'icon' => WP01_Content::get_image_src('icons/5/disable-feeds_m.jpg'),
        'path' => 'disable-feeds/disable-feeds.php',
		'analogs' =>  array(
            array(
                'name' => 'Clearfy — плагин для оптимизации WordPress',
                'icon' => WP01_Content::get_image_src('icons/5/clearfy_s.jpg'),
                'path' => 'clearfy/clearfy.php',
                'settings_link'  => '/options-general.php?page=quick_start-wbcr_clearfy',
            )
        ),
        'desc' => 'Отключает RSS ленту, через которую могут воровать контент',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-reading.php',
		'code_replace' => '
<strong>Замена функции &quot;Отключение RSS&quot;:</strong><br>
1. Откройте файл functions.php, находящийся в папке используемой темы (/wp-content/themes/название_темы/) или воспользуйтесь плагином <a href="/wp-admin/admin.php?page=wp01#step-6" target = "_blank">Code Snippets</a> (Шаг 6)<br>
2. Добавьте строчки<br>
<div class="tc">
// WP01: Отключение RSS<br>
function itsme_disable_feed() {<br>
 wp_die( __( &#039;No feed available, please visit the &lt;a href=&quot;&#039;. esc_url( home_url( &#039;/&#039; ) ) .&#039;&quot;&gt;homepage&lt;/a&gt;!&#039; ) );<br>
}<br>
add_action(&#039;do_feed&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
add_action(&#039;do_feed_rdf&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
add_action(&#039;do_feed_rss&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
add_action(&#039;do_feed_rss2&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
add_action(&#039;do_feed_atom&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
add_action(&#039;do_feed_rss2_comments&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
add_action(&#039;do_feed_atom_comments&#039;, &#039;itsme_disable_feed&#039;, 1);<br>
remove_action( &#039;wp_head&#039;, &#039;feed_links_extra&#039;, 3 );<br>
remove_action( &#039;wp_head&#039;, &#039;feed_links&#039;, 2 );<br><br>
</div>

<strong>Примечание:</strong><br>
1. В случае обновления темы повторите установку кода (не актуально при использовании плагина для добавления кода)<br>
2. При нахождении в конце файла functions.php закрытия блока &quot;?&gt;&quot; разместите код до него.<br>
3. Если после установки кода сайт выдаёт ошибку - удалите код и обновите страницу (Ctrl+F5)
		'
    ),
    array(
        'name' => 'Google XML Sitemaps',
        'icon' => WP01_Content::get_image_src('icons/5/google-sitemap-generator_m.jpg'),
        'path' => 'google-sitemap-generator/sitemap.php',
		        'analogs' =>  array(
            array(
                'name' => 'Sitemap by BestWebSoft',
                'icon' => WP01_Content::get_image_src('icons/5/google-sitemap-plugin_s.jpg'),
                'path' => 'google-sitemap-plugin/google-sitemap-plugin.php',
                'settings_link'  => '/admin.php?page=google-sitemap-plugin.php',
            ),
            array(
                'name' => 'Simple Wp Sitemap',
                'icon' => WP01_Content::get_image_src('icons/5/simple-wp-sitemap_s.jpg'),
                'path' => 'simple-wp-sitemap/simple-wp-sitemap.php',
                'settings_link'  => '/options-general.php?page=simpleWpSitemapSettings',
            ),
            array(
                'name' => 'Yoast SEO',
                'icon' => WP01_Content::get_image_src('icons/5/wp-seo_s.jpg'),
                'path' => 'wordpress-seo/wp-seo.php',
                'settings_link'  => '/admin.php?page=wpseo_dashboard',
            )
        ),
        'desc' => 'Удобная XML карта сайта',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://www.arnebrachhold.de/projects/wordpress-plugins/google-xml-sitemaps-generator/help/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://www.arnebrachhold.de/projects/wordpress-plugins/google-xml-sitemaps-generator/help/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://www.arnebrachhold.de/projects/wordpress-plugins/google-xml-sitemaps-generator/help/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=google-sitemap-generator%2Fsitemap.php',
		'code_replace' => '
<strong>Замена функции &quot;Sitemaps карта сайта:</strong><br>
1. Создайте в корне сайта файл sitemap.xml<br>
2. Отредактируйте файл добавив в него следующие строки<br>
<div class="tc">
&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;<br>
&lt;urlset xmlns=&quot;http://www.sitemaps.org/schemas/sitemap/0.9&quot;&gt;<br>
&lt;url&gt;<br>
&lt;loc&gt;http://site.ru&lt;/loc&gt;<br>
&lt;lastmod&gt;2019-12-17&lt;/lastmod&gt;<br>
&lt;changefreq&gt;daily&lt;/changefreq&gt;<br>
&lt;priority&gt;1.0&lt;/priority&gt;<br>
&lt;/url&gt;<br>
&lt;url&gt;<br>
&lt;loc&gt;http://site.ru/link1.php&lt;/loc&gt;<br>
&lt;lastmod&gt;2019-12-17&lt;/lastmod&gt;<br>
&lt;changefreq&gt;weekly&lt;/changefreq&gt;<br>
&lt;priority&gt;0.8&lt;/priority&gt;<br>
&lt;/url&gt;<br>
&lt;/urlset&gt;<br>
</div>
3. Измените код согласно значениям:<br>
http://site.ru - cтраница сайта<br>
2019-12-17 - последнее обновление страницы<br>
weekly - частота изменения страницы<br>
1.0 - приоритет страницы<br><br>

<strong>Примечание:</strong><br>
1. Для автоматического создания карты сайта воспользуйтесь онлайн-сервисом:<br>
<a href="http://www.xml-sitemaps.com/" target="_blank">http://www.xml-sitemaps.com/</a><br>
<a href="https://freesitemapgenerator.com/" target="_blank">https://freesitemapgenerator.com/</a>
		'
    ),
    array(
        'name' => 'Mihdan: No External Links',
        'icon' => WP01_Content::get_image_src('icons/5/mihdan-no-external-links_m.jpg'),
        'path' => 'mihdan-no-external-links/mihdan-noexternallinks.php',
		'analogs' =>  array(
            array(
                'name' => 'WP No External Links',
                'icon' => WP01_Content::get_image_src('icons/5/no-external-links_s.jpg'),
                'path' => 'no-external-links/no-external-links.php',
                'settings_link'  => '/options-general.php?page=no-external-links%2Fno-external-links-options.php',
            ),
            array(
                'name' => 'External Links — nofollow, noopener & new window',
                'icon' => WP01_Content::get_image_src('icons/5/wp-external-links_s.jpg'),
                'path' => 'wp-external-links/wp-external-links.php',
                'settings_link'  => '/admin.php?page=wpel-settings-page',
            ),
            array(
                'name' => 'Title and Nofollow For Links',
                'icon' => WP01_Content::get_image_src('icons/5/title-and-nofollow-for-links_s.jpg'),
                'path' => 'title-and-nofollow-for-links/title-and-nofollow-for-links.php',
                'settings_link'  => '',
            )
        ),
        'desc' => 'Преобразование внешних ссылок во внутренние и скрытие их от индексации',
        'rate' => 3,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/admin.php?page=mihdan-no-external-links',
    ),
    array(
        'name' => 'Yet Another Related Posts Plugin (YARPP)',
        'icon' => WP01_Content::get_image_src('icons/5/yarpp_m.jpg'),
        'path' => 'yet-another-related-posts-plugin/yarpp.php',
		'analogs' =>  array(
            array(
                'name' => 'Contextual Related Posts',
                'icon' => WP01_Content::get_image_src('icons/5/contextual-related-posts_s.jpg'),
                'path' => 'contextual-related-posts/contextual-related-posts.php',
                'settings_link'  => '/options-general.php?page=crp_options_page',
            ),
            array(
                'name' => 'Related Posts Thumbnails Plugin for WordPress',
                'icon' => WP01_Content::get_image_src('icons/5/related-posts-thumbnails_s.jpg'),
                'path' => 'related-posts-thumbnails/related-posts-thumbnails.php',
                'settings_link'  => '/admin.php?page=related-posts-thumbnails',
            ),
            array(
                'name' => 'Inline Related Posts',
                'icon' => WP01_Content::get_image_src('icons/5/intelly-related-posts_s.jpg'),
                'path' => 'intelly-related-posts/index.php',
                'settings_link'  => '/options-general.php?page=intelly-related-posts',
            )
        ),
        'desc' => 'Показ связанных с записью страниц',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=yarpp',
    ),
    array(
        'name' => 'Internal Link Juicer: SEO Auto Linker for WordPress',
        'icon' => WP01_Content::get_image_src('icons/5/wp-internal-linkjuicer_m.jpg'),
        'path' => 'internal-links/wp-internal-linkjuicer.php',
		'analogs' =>  array(
            array(
                'name' => 'WPA SEO Auto Linker',
                'icon' => WP01_Content::get_image_src('icons/5/wpa-seo-auto-linker_s.jpg'),
                'path' => 'wpa-seo-auto-linker/wpa-seo-auto-linker.php',
                'settings_link'  => '/options-general.php?page=wpa-seo-auto-linker.php',
            ),
            array(
                'name' => 'Link Whisper Free',
                'icon' => WP01_Content::get_image_src('icons/5/link-whisper_s.jpg'),
                'path' => 'link-whisper/link-whisper.php',
                'settings_link'  => '/admin.php?page=link_whisper_settings',
            )
        ),
        'desc' => 'Создание и контроль внутренних ссылок (перелинковка)',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://internallinkjuicer.com/docs/" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://internallinkjuicer.com/docs/" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://internallinkjuicer.com/docs/" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/admin.php?page=internal_link_juicer-settings',
    ),
    array(
        'name' => 'WordPress Popular Posts',
        'icon' => WP01_Content::get_image_src('icons/5/wordpress-popular-posts_m.jpg'),
        'path' => 'wordpress-popular-posts/wordpress-popular-posts.php',
		'analogs' =>  array(
            array(
                'name' => 'Trending/Popular Post Slider and Widget',
                'icon' => WP01_Content::get_image_src('icons/5/wp-trending-post-slider-and-widget_s.jpg'),
                'path' => 'wp-trending-post-slider-and-widget/wp-trending-post-slider-widget.php',
                'settings_link'  => '/admin.php?page=wtpsw-settings',
            ),
            array(
                'name' => 'Top 10 – Popular posts plugin for WordPress',
                'icon' => WP01_Content::get_image_src('icons/5/top-10_s.jpg'),
                'path' => 'top-10/top-10.php',
                'settings_link'  => '/admin.php?page=tptn_options_page',
            )
        ),
        'desc' => 'Отображение популярных постов (влияние на поведенческие факторы)',
        'rate' => 2,
        'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a><br>Документация:<br> 
<a href="https://github.com/cabrerahector/wordpress-popular-posts/wiki" target = "_blank"><strong>ENG</strong></a> &nbsp; 
<a href="https://translate.google.com/translate?sl=auto&tl=ru&u=https://github.com/cabrerahector/wordpress-popular-posts/wiki" target = "_blank"><strong>RUS(GT)</strong></a> &nbsp; 
<a href="https://translate.yandex.ru/translate?lang=en-ru&url=https://github.com/cabrerahector/wordpress-popular-posts/wiki" target = "_blank"><strong>RUS(YT)</strong></a><br>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=wordpress-popular-posts',
    ),
    array(
        'name' => 'Broken Link Checker',
        'icon' => WP01_Content::get_image_src('icons/5/broken-link-checker_m.jpg'),
        'path' => 'broken-link-checker/broken-link-checker.phpp',
		'analogs' =>  array(
            array(
                'name' => 'Link Checker',
                'icon' => WP01_Content::get_image_src('icons/5/wlink-checker_s.jpg'),
                'path' => 'link-checker/linkchecker.php',
                'settings_link'  => '/admin.php?page=link-checker',
            ),
            array(
                'name' => 'Advance Broken Link Checker | URL Shortener Clicks And Conversion Report [Link Manager ]',
                'icon' => WP01_Content::get_image_src('icons/5/easy-broken-link-checker_s.jpg'),
                'path' => 'easy-broken-link-checker/easy-broken-link-checker.php',
                'settings_link'  => '/admin.php?page=eblc_check_options',
            )
        ),
        'desc' => 'Отслеживание неработающих (битых) ссылок на сайте',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text'  => 'Активен, настроить',
        'settings_link'  => '/options-general.php?page=link-checker-settings',
    ),
    array(
        'icon' => WP01_Content::get_image_src('icons/5/tac_m.jpg'),
        'name' => 'Theme Authenticity Checker (TAC)',
        'path' => 'tac/tac.php',
		'analogs' =>  array(
            array(
                'name' => 'WP Authenticity Checker',
                'icon' => WP01_Content::get_image_src('icons/5/wp-authenticity-checker-wac_s.jpg'),
                'path' => 'wp-authenticity-checker-wac/wordpress_authenticity_checker.php',
                'settings_link'  => '/admin.php?page=wac_admin_panel',
            )
        ),
        'desc' => 'Сканирование тем на обратные ссылки и зашифрованный в base64 код<br><strong>Если возникает ошибка:</strong> после установки плагина, в файле /wp-content/plugins/tac/tac.php <br>замените в 158 строке "$themes = get_themes();" на "$themes = wp_get_themes();"',
        'rate' => 2,
		'link' => '<a href="https://plagin.wp01.ru/" target = "_blank">Инструкция готовится...</a>',
        'settings_text' => 'Активен, настроить',
        'settings_link' => '/themes.php?page=tac.php',
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

<h4>1. Произведите корректировку постоянных ссылок</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Выполните действия</div>
    <div class="collapse-body" style="display: none;">
    <pre>Если вы решили использовать плагин "<a href="#php-on-pages">.PHP on PAGES</a>" и тем самым установить PHP расширение в URL, то для полной активации вам нужно:
1. Перейти в административной части сайта в раздел "Настройки" -> "Постоянные ссылки"
2. Написать в графе "Произвольно" код <code>/%category%/%postname%.php</code></pre>
    </div>
</div>	
		

<h4>2. Внедрите корректные инструкции индексации</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Посмотреть файл robots.txt</div>
    <div class="collapse-body" style="display: none;">
        <pre>User-agent: *
Allow: /wp-content/themes/
Allow: */uploads
Allow: /*/*.js
Allow: /*/*.css
Allow: /wp-*.png
Allow: /wp-*.jpg
Allow: /wp-*.jpeg
Allow: /wp-*.gif
Allow: /wp-admin/admin-ajax.php
Disallow: /cgi-bin
Disallow: /?
Disallow: /wp-
Disallow: *?s=
Disallow: *&s=
Disallow: /search/
Disallow: /author/
Disallow: /users/
Disallow: */trackback
Disallow: */feed
Disallow: */rss
Disallow: */embed
Disallow: /xmlrpc.php
Disallow: *utm*=
Disallow: *openstat=


User-agent: GoogleBot
Allow: /wp-content/themes/
Allow: */uploads
Allow: /*/*.js
Allow: /*/*.css
Allow: /wp-*.png
Allow: /wp-*.jpg
Allow: /wp-*.jpeg
Allow: /wp-*.gif
Allow: /wp-admin/admin-ajax.php
Disallow: /cgi-bin
Disallow: /?
Disallow: /wp-
Disallow: *?s=
Disallow: *&s=
Disallow: /search/
Disallow: /author/
Disallow: /users/
Disallow: */trackback
Disallow: */feed
Disallow: */rss
Disallow: */embed
Disallow: /xmlrpc.php
Disallow: *utm*=
Disallow: *openstat=


User-agent: Yandex
Allow: /wp-content/themes/
Allow: */uploads
Allow: /*/*.js
Allow: /*/*.css
Allow: /wp-*.png
Allow: /wp-*.jpg
Allow: /wp-*.jpeg
Allow: /wp-*.gif
Allow: /wp-admin/admin-ajax.php
Disallow: /cgi-bin
Disallow: /?
Disallow: /wp-
Disallow: *?s=
Disallow: *&s=
Disallow: /search/
Disallow: /author/
Disallow: /users/
Disallow: */trackback
Disallow: */feed
Disallow: */rss
Disallow: */embed
Disallow: /xmlrpc.php
Clean-Param: utm_source&utm_medium&utm_campaign
Clean-Param: openstat

Sitemap: https://SAIT.RU/sitemap.xml
Sitemap: https://SAIT.RU/sitemap.xml.gz
Host: https://SAIT.RU
</pre>
    </div>
</div>

<h4>3. Проверьте склейку домена с префиксом "www" (для архивных версий CMS)</h4>
<div class="collapse collapsed">
    <div class="collapse-title collapse-toggler">Проанализируйте и внедрите код</div>
    <div class="collapse-body" style="display: none;">
	<br>
<strong>Проверка:</strong><br>
1. Откройте урл без www (например, https://wp01.ru), а затем с www (например, https://www.wp01.ru)<br>
2. Если по результатам урл изменится (например, открыли с www, а перебросило на без www) - всё отлично, склейка уже установлена.<br>

<br><strong>Внедрение склейки:</strong><br>
Если по результатам проверки переадресация не происходит и вы видите два самостоятельных урл (с www и без) - необходимо внедрить в файл htaccess. код:<br>

<br><strong>Переадресация домена с префиксом www на домен без www</strong><br>
<code>RewriteCond %{HTTP_HOST} ^www.wp01\.ru$ [NC]<br>
RewriteRule ^(.*)$ https://wp01.ru/$1 [R=301,L]</code><br>
Альтернатива:<br>
<code>RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]<br>
RewriteRule ^(.*)$ https://%1/$1 [R=301,L]</code><br>

<br><strong>Переадресация домена без префикса www на домен с www</strong><br>
<code>RewriteCond %{HTTP_HOST} ^wp01\.ru$ [NC]<br>
RewriteRule ^(.*)$ https://www.wp01.ru/$1 [R=301,L]</code><br>
Альтернатива:<br>
<code>RewriteCond %{HTTP_HOST} ^(.*)$ [NC]<br>
RewriteCond %{HTTP_HOST} !^www\. [NC]<br>
RewriteRule ^(.*)$ https://www.%1/$1 [R=301,L]</code>
    </div>
</div>	
		
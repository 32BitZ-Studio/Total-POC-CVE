<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

class WP01_Table
{
	
/* start new */

    /**
     * Print plugins backup table
     *
     * @param $titles array Titles array
     * @param $plugins array Files array
     */
    public static function build_backup_table($titles, $structure)
    {
        echo '<table class="wp-list-table widefat plugins">';
            self::backup_table_head($titles);
            self::backup_table_body($structure);
        echo '</table>';
    }

    /**
     * Print table head
     *
     * @param $titles array Titles array
    */
    public static function backup_table_head($titles)
    {
        echo '<thead>';
        echo '<tr>';
        foreach ($titles as $i => $title) {
            echo '<th>' . $title . '</th>';
        }
        echo '</tr>';
        echo '</thead>';
    }

    public static function backup_table_body($structure)
    {
        echo '<tbody>';
            foreach ($structure as $singleRow) {
                echo '<tr class="inactive">';
                    echo '<td>' . $singleRow['filename'] . '</td>';
                    echo '<td>' . $singleRow['path'] . '</td>';
                    echo '<td>' . $singleRow['comment'] . '</td>';
                    echo '<td style="text-align:left;">
                            <form  action="'. admin_url('admin-ajax.php') .'" method="GET" class="ajax-file-download">
                                <button  type="submit" class="button button-green">' . $singleRow['button_text'] . '</button>
                                <input hidden name="filename" value="' . $singleRow['filename'] . '"/>
                                <input hidden name="path" value="' . $singleRow['fullPath']. '"/>
                            </form>';
                    echo '</tr>';
            }
        echo '</tbody>';
    }
	
/* end new	*/

    /**
     * Print plugins table
     *
     * @param $titles array Titles array
     * @param $plugins array Plugins array
     */
    public static function the_table($titles, $plugins)
    {
        echo '<table class="wp-list-table widefat plugins">';

        self::the_head($titles);
        self::the_body($plugins);

        echo '</table>';
    }

    /**
     * Print table head
     *
     * @param $titles array Titles array
     */
    public static function the_head($titles)
    {
        echo '<thead>';
        echo '<tr>';
		$analogsExplain = __( 'Схожи по функционалу с рекомендованным плагином. Устанавливать если основной плагин работает не корректно', 'WP01' );

        foreach ($titles as $i => $title) {
            echo '<th ' . ( $i === 0 ? 'colspan=2' : ($i === 2 ? ' class="wp01-analog-tr" ': '') ) . '>' . $title . '' . ($i === 2 ? '<span class="analog-info analog-btn"><span class="analog-popup"><span class="analog-popup-text">'. $analogsExplain .'</span></span></span>': '') . '</th>';
        }

        echo '</tr>';
        echo '</thead>';
    }

    /**
     * Print table body
     *
     * @param $plugins array Plugins array
     */
    public static function the_body($plugins)
    {
		$word_absent = __( 'Отсутствует', 'WP01' );
		$word_open = __('Открыть', 'WP01');
		$word_analogInstalled = __( 'Установлен аналог', 'WP01' );
		$word_noAnalogs = __( 'Аналогов нет', 'WP01' );
		
		$code_replace_counter = 0;
        echo '<tbody>';
        foreach ($plugins as $plugin) {

            $name = WP01_Installer::get_info($plugin);
            $status = WP01_Content::get_plugin_status($plugin);
            $action = WP01_Installer::get_button($plugin, 'true');
            $isAnalog = false;
            
            $link = '<a href="https://plagin.wp01.ru" target="_blank">' . __('Инструкция по настройке', 'WP01') . '</a><br>' . __('разрабатывается...', 'WP01');

            echo '<tr class="inactive">';

            if (isset($plugin['icon']) && $plugin['icon']) echo '<td><img src="' . $plugin['icon'] . '"></td>';
            if (isset($plugin['name']) && $plugin['name']) echo '<td> <span class="td-name-piece">' . $name . '</span> </td>';
            if (isset($status['text']) && $status['text']) {
				$installed_check_status = false;
				if (isset($plugin['analogs']) && $plugin['analogs']) {
					foreach ($plugin['analogs'] as $analoge) {
						$analog_installed_status = WP01_Content::get_analog_status( $analoge );
						if ($analog_installed_status['is_active'] == 1 ) {
							$installed_check_status = true;
						}
					}
				}
				if ($installed_check_status) {
					echo '<td><span class="text-purple">'. $word_analogInstalled .'<span></td>';
				} else {
					echo '<td>' . $status['text'] . '</td>';
				}
			} 
            if (isset($plugin['analogs']) && $plugin['analogs']) {
				echo '<td class="wp01-analog-td">';
				foreach ($plugin['analogs'] as $analog) {
					$activate_status = false;

					// активирован ли основной плагин
					$plugin_status = WP01_Content::get_plugin_status( $plugin );


					if($installed_check_status || $plugin_status['is_active']) {
					//					  if(!isset($_COOKIE["message_watched"])) {

						$activate_status = true;
					//					  }
					}
					//				  print_r($installed_check_status);

					echo WP01_Installer::get_button_analog($analog, $activate_status);
				}
            '</td>'; }
            else { echo '<td class="wp01-analog-td">'. $word_noAnalogs .'</td>'; };
			if (isset($plugin['code_replace'])) { 
				echo '<td><span class="code-replace-level">'. (($plugin['replace_level'] == 'Полная') || ($plugin['replace_level'] == 'полная') ? '<b>'. __('Полная', 'WP01') .'</b>' : __('Частичная', 'WP01')) .'</span><span class="code-replace-btn" code-replace-btn='. $code_replace_counter .'> '. $word_open .'</span></td>';
			} else {
				echo '<td>' . $word_absent . '</td>';
			}
			
            if (isset($plugin['desc']) && $plugin['desc']) echo '<td>' . $plugin['desc'] . '</td>';
            if (isset($plugin['rate']) && $plugin['rate']) echo '<td>' . WP01_Content::get_plugin_priority($plugin['rate']) . '</td>';
            if (isset($action) && $action) {
				$activate_status = false;

				// активирован ли основной плагин
				$plugin_status = WP01_Content::get_plugin_status( $plugin );


				if($installed_check_status || $plugin_status['is_active']) {
				//					  if(!isset($_COOKIE["message_watched"])) {

					$activate_status = true;
				//					  }
				}
				 echo '<td class="text-center">' . WP01_Installer::get_button($plugin, $activate_status) . '</td>';
			};
            if (isset($plugin['link']) && $plugin['link']) echo '<td>' . $plugin['link'] . '</td>';
                else echo '<td>' . $link . '</td>';
			
            echo '</tr>';
			if (isset($plugin['code_replace'])) { 
				echo '<tr colspan="12" class="code-replace-slide code-replace-slide-'. $code_replace_counter .'"><td colspan="12"><span><span class="inner-code-replace-content">'. $plugin['code_replace'] .'</span></span></td></tr>';
				$code_replace_counter++;
			} 
        }
        echo '</tbody>';
    }
}
?>
<?php

/*
|--------------------------------------------------------------------------
| Vafpress Framework Constants
|--------------------------------------------------------------------------
*/

defined('VP_W2DC_VERSION')     or define('VP_W2DC_VERSION'    , '2.0-beta');
defined('VP_W2DC_NAMESPACE')   or define('VP_W2DC_NAMESPACE'  , 'VP_W2DC_');
defined('VP_W2DC_DIR')         or define('VP_W2DC_DIR'        , W2DC_PATH . 'vafpress-framework');
defined('VP_W2DC_DIR_NAME')    or define('VP_W2DC_DIR_NAME'   , basename(VP_W2DC_DIR));
defined('VP_W2DC_IMAGE_DIR')   or define('VP_W2DC_IMAGE_DIR'  , VP_W2DC_DIR . '/public/img');
defined('VP_W2DC_CONFIG_DIR')  or define('VP_W2DC_CONFIG_DIR' , VP_W2DC_DIR . '/config');
defined('VP_W2DC_DATA_DIR')    or define('VP_W2DC_DATA_DIR'   , VP_W2DC_DIR . '/data');
defined('VP_W2DC_CLASSES_DIR') or define('VP_W2DC_CLASSES_DIR', VP_W2DC_DIR . '/classes');
defined('VP_W2DC_VIEWS_DIR')   or define('VP_W2DC_VIEWS_DIR'  , VP_W2DC_DIR . '/views');
defined('VP_W2DC_INCLUDE_DIR') or define('VP_W2DC_INCLUDE_DIR', VP_W2DC_DIR . '/includes');

// finally framework base url
//$vp_w2dc_url         = trim(plugins_url('/', __FILE__), '/');

defined('VP_W2DC_URL')         or define('VP_W2DC_URL'        , W2DC_URL . 'vafpress-framework');
defined('VP_W2DC_PUBLIC_URL')  or define('VP_W2DC_PUBLIC_URL' , VP_W2DC_URL        . '/public');
defined('VP_W2DC_IMAGE_URL')   or define('VP_W2DC_IMAGE_URL'  , VP_W2DC_PUBLIC_URL . '/img');
defined('VP_W2DC_INCLUDE_URL') or define('VP_W2DC_INCLUDE_URL', VP_W2DC_URL        . '/includes');

// Get the start time and memory usage for profiling
defined('VP_W2DC_START_TIME')  or define('VP_W2DC_START_TIME', microtime(true));
defined('VP_W2DC_START_MEM')   or define('VP_W2DC_START_MEM',  memory_get_usage());

/**
 * EOF
 */
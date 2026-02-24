<?php
/* phpFlickr Class 1.2.1
 * Written by Dan Coulter (dan@dancoulter.com)
 * Sourceforge Project Page: http://www.sourceforge.net/projects/phpflickr/
 * Released under GNU General Public License (http://www.gnu.org/copyleft/gpl.html)
 * For more information about the class and upcoming tools and toys using it,
 * visit http://www.phpflickr.com/ or http://phpflickr.sourceforge.net
 *
 *     For installation instructions, open the README.txt file packaged with this
 *     class. If you don't have a copy, you can see it at:
 *     http://www.phpflickr.com/README.txt
 *
 *     Please submit all problems or questions to the Help Forum on my project page:
 *         http://sourceforge.net/forum/forum.php?forum_id=469652
 * 
 */
 
require_once("xml.php");

class phpFlickr {
    var $api_key;
    var $REST = "http://www.flickr.com/services/rest/";
    var $xml_parser;
    var $req;
    var $response;
    var $parsed_response;
    var $email;
    var $password;
    var $cache = false;
    var $cache_db = null;
    var $cache_table = null;
    var $cache_dir = null;
    var $cache_expire = null;
    var $die_on_error;
    var $error_num;
    Var $error_msg;
    
    
    function phpFlickr ($api_key, $die_on_error = true) 
    {
        //The API Key must be set before any calls can be made.  You can 
        //get your own at http://www.flickr.com/services/api/misc.api_keys.html
        $this->api_key = $api_key;
        $this->die_on_error = $die_on_error;
        
        //All calls to the API are done via the POST method using the PEAR::HTTP_Request package.
        require_once "HTTP/Request.php";
        $this->req =& new HTTP_Request();
        $this->req->setMethod(HTTP_REQUEST_METHOD_POST);
        
        //setup XML parser using Aaron Colflesh's XML class.
        $this->xml_parser = new xml(false, true, true);
    }
    
    function login($email = NULL, $password = NULL)
    {
        //Sets login information and tests the login.
        $this->email = $email;
        $this->password = $password;
        return $this->test_login();
    }
    
    function enableCache($type, $connection, $cache_expire = 600, $table = "flickr_cache") 
    {
        // Turns on caching.  $type must be either "db" (for database caching) or "fs" (for filesystem).
        // When using db, $connection must be a PEAR::DB connection string. Example:
        //      "mysql://user:password@server/database"
        // If the $table, doesn't exist, it will attempt to create it.
        // When using file system, caching, the $connection is the folder that the web server has write
        // access to. Use absolute paths for best results.  Relative paths may have unexpected behavior 
        // when you include this.  They'll usually work, you'll just want to test them.
        if ($type == "db") {
            require_once "DB.php";
            $db =& DB::connect($connection);
            if (PEAR::isError($db)) {
                die($db->getMessage());
            }
            
            $db->query("
                CREATE TABLE IF NOT EXISTS `$table` (
                    `request` CHAR( 35 ) NOT NULL ,
                    `response` TEXT NOT NULL ,
                    `expiration` DATETIME NOT NULL ,
                    INDEX ( `request` )
                ) TYPE = MYISAM");
            $db->query("DELETE FROM $table WHERE expiration < DATE_SUB(NOW(), INTERVAL $cache_expire second)");
            $this->cache = "db";
            $this->cache_db = $db;
            $this->cache_table = $table;
        } elseif ($type = "fs") {
            $this->cache = "fs";
            chdir($connection);
            $this->cache_dir = getcwd();
            if ($dir = opendir("./")) {
                while ($file = readdir($dir)) {
                    if (substr($file, -6) == ".cache" && ((filemtime($file) + $cache_expire) < time()) ) {
                        unlink($file);
                    }
                }
            }
        }
        $this->cache_expire = $cache_expire;
    }
    
    function getCached ($request) 
    {
        //Checks the database or filesystem for a cached result to the request.
        //If there is no cache result, it returns a value of false. If it finds one
        //it returns the unparsed XML.
        $reqhash = md5(serialize($request));
        if ($this->cache == "db") {
            if($this->cache_db->getOne("SELECT COUNT(*) FROM " . $this->cache_table . " WHERE request = '" . $reqhash . "'")) {
                return $this->cache_db->getOne("SELECT response FROM " . $this->cache_table . " WHERE request = '" . $reqhash . "'");
            }
        } elseif ($this->cache == "fs") {
            $file = $this->cache_dir . "/" . $reqhash . ".cache";
            if (file_exists($file)) {
                return file_get_contents($file);
            }
        }
        return false;
    }
    
    function cache ($request, $response) 
    {
        //Caches the unparsed XML of a request.
        $reqhash = md5(serialize($request));
        if ($this->cache == "db") {
            $this->cache_db->query("DELETE FROM $this->cache_table WHERE request = '$reqhash'");
            $sql = "INSERT INTO " . $this->cache_table . " (request, response, expiration) VALUES ('$reqhash', '" . str_replace("'", "''", $response) . "', '" . strftime("%Y-%m-%d %T") . "')";
            $this->cache_db->query($sql);
        } elseif ($this->cache == "fs") {
            $file = $this->cache_dir . "/" . $reqhash . ".cache";
            $fstream = fopen($file, "w");
            $result = fwrite($fstream,$response);
            fclose($fstream);
            return $result;
        }
        return false;
    }
    
    function request ($command, $args = array(), $nocache = false) 
    {
        //Sends a request to Flickr's REST endpoint via POST.
        $this->req->setURL($this->REST);
        $this->req->clearPostData();
        if (substr($command,0,7) != "flickr.") {
            $command = "flickr." . $command;
        }
        
        //Process arguments, including method and login data.
        $args = array_merge(array("method" => $command, "api_key" => $this->api_key, "email" => $this->email, "password" => $this->password), $args);
        if(!($this->response = $this->getCached($args)) || $nocache) {
            foreach ($args as $key => $data) {
                $this->req->addPostData($key, $data);
            }
        
            //Send Requests
            if ($this->req->sendRequest()) {
                $this->response = $this->req->getResponseBody();
                $this->cache($args, $this->response);
            } else {
                die("There has been a problem sending your command to the server.");
            }
        }
        return $this->response;
    }
    
    function parse_response ($xml = NULL) 
    {
        //Sends response data through XML parser and returns an associative array.
        if ($xml === NULL) {
            $xml = $this->response;
        }
        $this->parsed_response = $this->xml_parser->parse($xml);
        
        //Check for an error and die if it finds one.
        if (!empty($this->parsed_response['rsp']['err']) && $this->die_on_error) {
            die("The Flickr API returned error code #" . $this->parsed_response['rsp']['err']['code'] . ": " . $this->parsed_response['rsp']['err']['msg']);
        } elseif (!empty($this->parsed_response['rsp']['err'])) {
			$this->error_code = $this->parsed_response['rsp']['err']['code'];
			$this->error_msg = "The Flickr API returned error code #" . $this->parsed_response['rsp']['err']['code'] . ": " . $this->parsed_response['rsp']['err']['msg'];
			return false;
        } else {
			$this->error_code = false;
			$this->error_msg = false;
        }
        
        return $this->parsed_response['rsp'];
    }
    
    function getErrorCode() {
		// Returns the error code of the last call.  If the last call did not
		// return an error. This will return a false boolean.
		return $this->error_code();
    }
    
    function getErrorMsg() {
		// Returns the error message of the last call.  If the last call did not
		// return an error. This will return a false boolean.
		return $this->error_code();
    }
    
    /* These functions are front ends for the flickr calls */
    
    function buildPhotoURL ($photo, $size = "Medium") 
    {
        //receives an array (can use the individual photo data returned 
        //from an API call) and returns a URL (doesn't mean that the 
        //file size exists)
        $url = "http://photos" . $photo['server'] . ".flickr.com/" . $photo['id'] . "_" . $photo['secret'];
        switch (strtolower($size)) {
            case "square":
                $url .= "_s";
                break;
            case "thumbnail":
                $url .= "_t";
                break;
            case "small":
                $url .= "_m";
                break;
            case "medium":
                $url .= "";
                break;
            case "large":
                $url .= "_b";
                break;
            case "original":
                $url .= "_o";
                break;
        }
        $url .= ".jpg";
        return $url;
    }
    
    /* 
        These functions are the direct implementations of flickr calls.
        For method documentation, including arguments, visit the address
        included in a comment in the function. 
    */
    
    /* Blogs methods */
    function blogs_getList () 
    {
        /* http://www.flickr.com/services/api/flickr.blogs.getList.html */
        $this->request("flickr.blogs.getList");
        $this->parse_response();
        return $this->parsed_response['rsp']["blogs"]["blog"];
    }
    
    function blogs_postPhoto($blog_id, $photo_id, $title, $description, $blog_password = NULL) {
        /* http://www.flickr.com/services/api/flickr.blogs.postPhoto.html */
        $this->request("flickr.blogs.postPhoto", array("blog_id"=>$blog_id, "photo_id"=>$photo_id, "title"=>$title, "description"=>$description, "blog_password"=>$blog_password));
        $this->parse_response();
        return true;
    }
    
    /* Contacts Methods */
    function contacts_getList () 
    {
        /* http://www.flickr.com/services/api/flickr.contacts.getList.html */
        $this->request("flickr.contacts.getList");
        $this->parse_response();
        return $this->parsed_response['rsp']["contacts"]["contact"];
    }
    
    function contacts_getPublicList($user_id) 
    {
        /* http://www.flickr.com/services/api/flickr.contacts.getPublicList.html */
        $this->request("flickr.contacts.getPublicList", array("user_id"=>$user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["contacts"]["contact"];
    }
    
    /* Favorites Methods */
    function favorites_add ($photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.favorites.add.html */
        $this->request("flickr.favorites.add", array("photo_id"=>$photo_id));
        $this->parse_response();
        return true;
    }
    
    function favorites_getList($user_id = NULL, $extras = NULL, $per_page = NULL, $page = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.favorites.getList.html */
        if (is_array($extras)) { $extras = implode(",", $extras); }
        $this->request("flickr.favorites.getList", array("user_id"=>$user_id, "extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        return $this->parsed_response['rsp']["photos"]["photo"];
    }
    
    function favorites_getPublicList($user_id = NULL, $extras = NULL, $per_page = NULL, $page = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.favorites.getPublicList.html */
        if (is_array($extras)) {
            $extras = implode(",", $extras);
        }
        $this->request("flickr.favorites.getPublicList", array("user_id"=>$user_id, "extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        return $this->parsed_response['rsp']["photos"]["photo"];
    }
    
    function favorites_remove($photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.favorites.remove.html */
        if (is_array($extras)) {
            $extras = implode(",", $extras);
        }
        $this->request("flickr.favorites.remove", array("photo_id"=>$photo_id));
        $this->parse_response();
        return true;
    }
    
    /* Groups Methods */
    function groups_browse ($cat_id = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.groups.browse.html */
        $this->request("flickr.groups.browse", array("cat_id"=>$cat_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["category"];
    }
    
    function groups_getActiveList () 
    {
        /* http://www.flickr.com/services/api/flickr.groups.getActiveList.html */
        $this->request("flickr.groups.getActiveList");
        $this->parse_response();
        return $this->parsed_response['rsp']["activegroups"];
    }
    
    function groups_getInfo ($group_id) 
    {
        /* http://www.flickr.com/services/api/flickr.groups.getInfo.html */
        $this->request("flickr.groups.getInfo", array("group_id"=>$group_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["group"];
    }
    
    /* Groups Methods */
    function groups_pools_add ($photo_id, $group_id) 
    {
        /* http://www.flickr.com/services/api/flickr.groups.pools.add.html */
        $this->request("flickr.groups.pools.add", array("photo_id"=>$photo_id, "group_id"=>$group_id));
        $this->parse_response();
        return true;
    }
    
    function groups_pools_getContext ($photo_id, $group_id) 
    {
        /* http://www.flickr.com/services/api/flickr.groups.pools.getContext.html */
        $this->request("flickr.groups.pools.getContext", array("photo_id"=>$photo_id, "group_id"=>$group_id));
        $this->parse_response();
        return $this->parsed_response['rsp'];
    }
    
    function groups_pools_getGroups () 
    {
        /* http://www.flickr.com/services/api/flickr.groups.pools.getGroups.html */
        $this->request("flickr.groups.pools.getGroups");
        $this->parse_response();
        return $this->parsed_response['rsp']["groups"]["group"];
    }
    
    function groups_pools_getPhotos ($group_id, $tags = NULL, $extras = NULL, $per_page = NULL, $page = NULL) 
    {
    /* http://www.flickr.com/services/api/flickr.groups.pools.getPhotos.html */
        if (is_array($extras)) {
            $extras = implode(",", $extras);
        }
        $this->request("flickr.groups.pools.getPhotos", array("group_id"=>$group_id, "tags"=>$tags, "extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        return $this->parsed_response['rsp']["photos"];
    }
    
    function groups_pools_remove ($photo_id, $group_id) 
    {
        /* http://www.flickr.com/services/api/flickr.groups.pools.remove.html */
        $this->request("flickr.groups.pools.remove", array("photo_id"=>$photo_id, "group_id"=>$group_id));
        $this->parse_response();
        return true;
    }
    
    /* People methods */
    function people_findByEmail ($find_email) 
    {
        /* http://www.flickr.com/services/api/flickr.people.findByEmail.html */
        $this->request("flickr.people.findByEmail", array("find_email"=>$find_email));
        $this->parse_response();
        return $this->parsed_response['rsp']["user"]["nsid"];
    }
    
    function people_findByUsername ($username) 
    {
        /* http://www.flickr.com/services/api/flickr.people.findByUsername.html */
        $this->request("flickr.people.findByUsername", array("username"=>$username));
        $this->parse_response();
        return $this->parsed_response['rsp']["user"]["nsid"];
    }
    
    function people_getInfo($user_id) 
    {
        /* http://www.flickr.com/services/api/flickr.people.getInfo.html */
        $this->request("flickr.people.getInfo", array("user_id"=>$user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["person"];
    }
    
    function people_getOnlineList() 
    {
        /* http://www.flickr.com/services/api/flickr.people.getOnlineList.html */
        $this->request("flickr.people.getOnlineList");
        $this->parse_response();
        return $this->parsed_response['rsp']["online"];
    }
    
    function people_getPublicGroups($user_id) 
    {
        /* http://www.flickr.com/services/api/flickr.people.getPublicGroups.html */
        $this->request("flickr.people.getPublicGroups", array("user_id"=>$user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']['groups'];
    }
    
    function people_getPublicPhotos($user_id, $extras = NULL, $per_page = NULL, $page = NULL) {
        /* http://www.flickr.com/services/api/flickr.people.getPublicPhotos.html */
        if (is_array($extras)) { 
            $extras = implode(",", $extras); 
        }
        
        $this->request("flickr.people.getPublicPhotos", array("user_id"=>$user_id, "extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        $result = $this->parsed_response['rsp']['photos'];
        if (!empty($result['photo']['id'])) {
            $tmp = $result['photo'];
            unset($result['photo']);
            $result['photo'][] = $tmp;
        }
        return $result;
    }
    
    /* Photos Methods */
    function photos_addTags ($photo_id, $tags) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.addTags.html */
        $this->request("flickr.photos.addTags", array("photo_id"=>$photo_id, "tags"=>$tags));
        $this->parse_response();
        return true;
    }
    
    function photos_getContactsPhotos ($count = NULL, $just_friends = NULL, $single_photo = NULL, $include_self = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getContactsPhotos.html */
        $this->request("flickr.photos.getContactsPhotos", array("count"=>$count, "just_friends"=>$just_friends, "single_photo"=>$single_photo, "include_self"=>$include_self));
        $this->parse_response();
        $result = $this->parsed_response['rsp']['photos'];
        if (!empty($result['photo']['id'])) {
            $tmp = $result['photo'];
            unset($result['photo']);
            $result['photo'][] = $tmp;
        }
        return $result['photo'];
    }
    
    function photos_getContactsPublicPhotos ($user_id, $count = NULL, $just_friends = NULL, $single_photo = NULL, $include_self = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getContactsPublicPhotos.html */
        $this->request("flickr.photos.getContactsPublicPhotos", array("user_id"=>$user_id, "count"=>$count, "just_friends"=>$just_friends, "single_photo"=>$single_photo, "include_self"=>$include_self));
        $this->parse_response();
        $result = $this->parsed_response['rsp']['photos'];
        if (!empty($result['photo']['id'])) {
            $tmp = $result['photo'];
            unset($result['photo']);
            $result['photo'][] = $tmp;
        }
        return $result['photo'];
    }
    
    function photos_getContext ($photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getContext.html */
        $this->request("flickr.photos.getContext", array("photo_id"=>$photo_id));
        $this->parse_response();
        return $this->parsed_response['rsp'];
    }
    
    function photos_getCounts ($dates = NULL, $taken_dates = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getCounts.html */
        $this->request("flickr.photos.getCounts", array("dates"=>$dates, "taken_dates"=>$taken_dates));
        $this->parse_response();
        return $this->parsed_response['rsp']["photocounts"]["photocount"];
    }
    
    function photos_getExif ($photo_id, $secret = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getExif.html */
        $this->request("flickr.photos.getExif", array("photo_id"=>$photo_id, "secret"=>$secret));
        $this->parse_response();
        return $this->parsed_response['rsp']["photo"];
    }
    
    function photos_getInfo($photo_id, $secret = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getInfo.html */
        $this->request("flickr.photos.getInfo", array("photo_id"=>$photo_id, "secret"=>$secret));
        $this->parse_response();
        return $this->parsed_response['rsp']["photo"];
    }
    
    function photos_getNotInSet($extras = NULL, $per_page = NULL, $page = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getNotInSet.html */
        if (is_array($extras)) { 
            $extras = implode(",", $extras); 
        }
        $this->request("flickr.photos.getNotInSet", array("extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        return $this->parsed_response['rsp']["photos"];
    }
    
    function photos_getPerms($photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getPerms.html */
        $this->request("flickr.photos.getPerms", array("photo_id"=>$photo_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["perms"];
    }
    
    function photos_getRecent($extras = NULL, $per_page = NULL, $page = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getRecent.html */
        if (is_array($extras)) {
            $extras = implode(",", $extras);
        }
        
        $this->request("flickr.photos.getRecent", array("extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        $result = $this->parsed_response['rsp']['photos'];
        if (!empty($result['photo']['id'])) {
            $tmp = $result['photo'];
            unset($result['photo']);
            $result['photo'][] = $tmp;
        }
        return $result;
    }
    
    function photos_getSizes($photo_id, $secret = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getSizes.html */
        $this->request("flickr.photos.getSizes", array("photo_id"=>$photo_id));
        $this->parse_response();
        foreach($this->parsed_response['rsp']["sizes"]['size'] as $size) {
            $result[$size["label"]] = $size;
        }
        return $result;
    }
    
    function photos_getUntagged($extras = NULL, $per_page = NULL, $page = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.getUntagged.html */
        if (is_array($extras)) { 
            $extras = implode(",", $extras); 
        }
        $this->request("flickr.photos.getUntagged", array("extras"=>$extras, "per_page"=>$per_page, "page"=>$page));
        $this->parse_response();
        return $this->parsed_response['rsp']["photos"];
    }
    
    function photos_removeTag($tag_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.removeTag.html */
        $this->request("flickr.photos.removeTag", array("tag_id"=>$tag_id));
        $this->parse_response();
        return true;
    }
    
    function photos_search($args) 
    {
        /* This function strays from the method of arguments that I've
         * used in the other functions for the fact that there are just
         * so many arguments to this API method. What you'll need to do
         * is pass an associative array to the function containing the
         * arguments you want to pass to the API.  For example:
         *   $photos = $f->photos_search(array("tags"=>"brown cow", "tag_mode"=>"any"));
         * This will return photos tagged with either "brown" or "cow"
         * or both. See the API documentation (link below) for a full 
         * list of arguments.
         */
         
        /* http://www.flickr.com/services/api/flickr.photos.search.html */
        $this->request("flickr.photos.search", $args);
        $this->parse_response();
        $result = $this->parsed_response['rsp']['photos'];
        if (!empty($result['photo']['id'])) {
            $tmp = $result['photo'];
            unset($result['photo']);
            $result['photo'][] = $tmp;
        }
        return $result;
    }
    
    function photos_setDates($photo_id, $date_posted = NULL, $date_taken = NULL, $date_taken_granularity = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.setDates.html */
        $this->request("flickr.photos.setDates", array("photo_id"=>$photo_id, "date_posted"=>$date_posted, "date_taken"=>$date_taken, "date_taken_granularity"=>$date_taken_granularity));
        $this->parse_response();
        return true;
    }
    
    function photos_setMeta($photo_id, $title, $description) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.setMeta.html */
        $this->request("flickr.photos.setMeta", array("photo_id"=>$photo_id, "title"=>$title, "description"=>$description));
        $this->parse_response();
        return true;
    }
    
    function photos_setPerms($photo_id, $is_public, $is_friend, $is_family, $perm_comment, $perm_addmeta) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.setPerms.html */
        $this->request("flickr.photos.setPerms", array("photo_id"=>$photo_id, "is_public"=>$is_public, "is_friend"=>$is_friend, "is_family"=>$is_family, "perm_comment"=>$perm_comment, "perm_addmeta"=>$perm_addmeta));
        $this->parse_response();
        return true;
    }
    
    function photos_setTags($photo_id, $tags) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.setTags.html */
        $this->request("flickr.photos.setTags", array("photo_id"=>$photo_id, "tags"=>$tags));
        $this->parse_response();
        return true;
    }
    
    /* Photos - Notes Methods */
    function photos_licenses_getInfo() 
    {
        /* http://www.flickr.com/services/api/flickr.photos.licenses.getInfo.html */
        $this->request("flickr.photos.licenses.getInfo");
        $this->parse_response();
        return $this->parsed_response['rsp']['licenses'];
    }
    
    /* Photos - Notes Methods */
    function photos_notes_add($photo_id, $note_x, $note_y, $note_w, $note_h, $note_text) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.notes.add.html */
        $this->request("flickr.photos.notes.add", array("photo_id" => $photo_id, "note_x" => $note_x, "note_y" => $note_y, "note_w" => $note_w, "note_h" => $note_h, "note_text" => $note_text));
        $this->parse_response();
        return $this->parsed_response['rsp']['note']['id'];
    }
    
    function photos_notes_delete($note_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.notes.delete.html */
        $this->request("flickr.photos.notes.delete", array("note_id" => $note_id));
        $this->parse_response();
        return true;
    }
    
    function photos_notes_edit($note_id, $note_x, $note_y, $note_w, $note_h, $note_text) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.notes.edit.html */
        $this->request("flickr.photos.notes.edit", array("note_id" => $note_id, "note_x" => $note_x, "note_y" => $note_y, "note_w" => $note_w, "note_h" => $note_h, "note_text" => $note_text));
        $this->parse_response();
        return true;
    }
    
    /* Photos - Transform Methods */
    function photos_transform_rotate($photo_id, $degrees) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.transform.rotate.html */
        $this->request("flickr.photos.transform.rotate", array("photo_id" => $photo_id, "degrees" => $degrees));
        $this->parse_response();
        return true;
    }
    
    /* Photosets Methods */
    function photosets_addPhoto($photoset_id, $photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.addPhoto.html */
        $this->request("flickr.photosets.addPhoto", array("photoset_id" => $photoset_id, "photo_id" => $photo_id));
        $this->parse_response();
        return true;
    }
    
    function photosets_create($title, $description, $primary_photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.create.html */
        $this->request("flickr.photosets.create", array("title" => $title, "primary_photo_id" => $primary_photo_id, "description" => $description));
        $this->parse_response();
        return $this->parsed_response['rsp']['photoset'];
    }
    
    function photosets_delete($photoset_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.delete.html */
        $this->request("flickr.photosets.delete", array("photoset_id" => $photoset_id));
        $this->parse_response();
        return true;
    }
    
    function photosets_editMeta($photoset_id, $title, $description = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.editMeta.html */
        $this->request("flickr.photosets.editMeta", array("photoset_id" => $photoset_id, "title" => $title, "description" => $description));
        $this->parse_response();
        return true;
    }
    
    function photosets_editPhotos($photoset_id, $primary_photo_id, $photo_ids) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.editPhotos.html */
        $this->request("flickr.photosets.editPhotos", array("photoset_id" => $photoset_id, "primary_photo_id" => $primary_photo_id, "photo_ids" => $photo_ids));
        $this->parse_response();
        return true;
    }
    
    function photosets_getContext($photo_id, $photoset_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.getContext.html */
        $this->request("flickr.photosets.getContext", array("photo_id" => $photo_id, "photoset_id" => $photoset_id));
        $this->parse_response();
        return $this->parsed_response['rsp'];
    }
    
    function photosets_getInfo($photoset_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.getInfo.html */
        $this->request("flickr.photosets.getInfo", array("photoset_id" => $photoset_id));
        $this->parse_response();
        return $this->parsed_response['rsp']['photoset'];
    }
    
    function photosets_getList($user_id = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.getList.html */
        $this->request("flickr.photosets.getList", array("user_id" => $user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']['photosets'];
    }
    
    function photosets_getPhotos($photoset_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.getPhotos.html */
        $this->request("flickr.photosets.getPhotos", array("photoset_id" => $photoset_id));
        $this->parse_response();
        return $this->parsed_response['rsp']['photoset'];
    }
    
    function photosets_orderSets($photoset_ids) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.orderSets.html */
        if (is_array($photoset_ids)) {
            $photoset_ids = implode(",", $photoset_ids);
        }
        $this->request("flickr.photosets.orderSets", array("photoset_ids" => $photoset_ids));
        $this->parse_response();
        return true;
    }
    
    function photosets_removePhoto($photoset_id, $photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.photosets.removePhoto.html */
        $this->request("flickr.photosets.removePhoto", array("photoset_id" => $photoset_id, "photo_id" => $photo_id));
        $this->parse_response();
        return true;
    }
    
    /* Reflection Methods */
    function reflection_getMethodInfo($method_name) 
    {
        /* http://www.flickr.com/services/api/flickr.reflection.getMethodInfo.html */
        $this->request("flickr.reflection.getMethodInfo", array("method_name" => $method_name));
        $this->parse_response();
        return $this->parsed_response['rsp']['method'];
    }
    
    function reflection_getMethods() 
    {
        /* http://www.flickr.com/services/api/flickr.reflection.getMethods.html */
        $this->request("flickr.reflection.getMethods");
        $this->parse_response();
        return $this->parsed_response['rsp']['methods'];
    }
    
    /* Tags Methods */
    function tags_getListPhoto($photo_id) 
    {
        /* http://www.flickr.com/services/api/flickr.tags.getListPhoto.html */
        $this->request("flickr.tags.getListPhoto", array("photo_id" => $photo_id));
        $this->parse_response();
        return $this->parsed_response['rsp']['photo'];
    }
    
    function tags_getListUser($user_id = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.tags.getListUser.html */
        $this->request("flickr.tags.getListUser", array("user_id" => $user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']['who'];
    }
    
    function tags_getListUserPopular($user_id = NULL, $count = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.tags.getListUserPopular.html */
        $this->request("flickr.tags.getListUserPopular", array("user_id" => $user_id, "count" => $count));
        $this->parse_response();
        return $this->parsed_response['rsp']['who'];
    }
    
    function tags_getRelated($tag) 
    {
        /* http://www.flickr.com/services/api/flickr.tags.getRelated.html */
        $this->request("flickr.tags.getRelated", array("tag" => $tag));
        $this->parse_response();
        return $this->parsed_response['rsp']['tags'];
    }
    
    function test_echo($args = array()) 
    {
        /* http://www.flickr.com/services/api/flickr.test.echo.html */
        $this->request("flickr.test.echo", $args);
        $this->parse_response();
        return $this->parsed_response['rsp'];
    }
    
    function test_login() 
    {
        /* http://www.flickr.com/services/api/flickr.test.login.html */
        $this->request("flickr.test.login");
        $this->parse_response();
        return $this->parsed_response['rsp']['user'];
    }
    
    function urls_getGroup($group_id) 
    {
        /* http://www.flickr.com/services/api/flickr.urls.getGroup.html */
        $this->request("flickr.urls.getGroup", array("group_id"=>$group_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["group"]["url"];
    }
    
    function urls_getUserPhotos($user_id = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.urls.getUserPhotos.html */
        $this->request("flickr.urls.getUserPhotos", array("user_id"=>$user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["user"]["url"];
    }
    
    function urls_getUserProfile($user_id = NULL) 
    {
        /* http://www.flickr.com/services/api/flickr.urls.getUserProfile.html */
        $this->request("flickr.urls.getUserProfile", array("user_id"=>$user_id));
        $this->parse_response();
        return $this->parsed_response['rsp']["user"]["url"];
    }
    
    function urls_lookupGroup($url) 
    {
        /* http://www.flickr.com/services/api/flickr.urls.lookupGroup.html */
        $this->request("flickr.urls.lookupGroup", array("url"=>$url));
        $this->parse_response();
        return $this->parsed_response['rsp']["group"];
    }
    
    function urls_lookupUser($url) 
    {
        /* http://www.flickr.com/services/api/flickr.photos.notes.edit.html */
        $this->request("flickr.urls.lookupUser", array("url"=>$url));
        $this->parse_response();
        return $this->parsed_response['rsp']["user"];
    }
}


?>

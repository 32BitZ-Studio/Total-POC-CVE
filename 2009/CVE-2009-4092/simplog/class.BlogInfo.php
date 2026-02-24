<?php 

	/*******************************************************************
	 * $Id: class.BlogInfo.php,v 1.14 2006/04/22 10:33:14 f-bomb Exp $
	 *
	 * class.BlogInfo.php
	 * Author: Jason Buberel
	 * Copyright (C) 2003, Jason Buberel
	 * jason@buberel.org
	 * http://www.buberel.org/
	 *
	 *******************************************************************
	 This program is free software; you can redistribute it and/or modify it
	 under the terms of the GNU General Public License as published by the
	 Free Software Foundation; either version 2 of the License, or (at your
	 option) any later version.

	 This program is distributed in the hope that it will be useful, but
	 WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 General Public License for more details.

	 You should have received a copy of the GNU General Public License along
	 with this program; if not, write to the Free Software Foundation, Inc.,
	 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
	 *******************************************************************
	 *
	 * This class is used to represent a single weblog. It gives the
     * developer access to all of the normal properties of the weblog.
     * Through the use of the required BlogEntry class, you should be able
     * to access all the data related to this particular weblog.
     *
     * To use BlogInfo, you create a new instance using the provided
     * constructor:
     *  include_once("class.BlogInfo.php");
     *  $blogId = 2;
     *  $myBlog = new BlogInfo($blogId);
     *
     * Once instantiated, the BlogInfo instance can be used to obtain
     * information about the blog:
     *
	 *  $myTitle = $myBlog->getBlogTitle();
     *
     * The three most useful methods are those used to retrieve BlogEntries:
     *
     *  $someBlogEntry = $myBlog->getBlogEntry(200); // fetch the 200th blog entry.
     *  $blogEntryList = $myBlog->getLastNEntries(10); // fetch the 10 most recent
     *                                                 // blog entries.
     *  foreach ($blogEntryList as $blogEntry) {
     *      print "Blog Entry Title: ($blogEntry->entryId) $blogEntry->entryTitle<br/>";
     *  }
	 */

include_once("lib.php");
include_once("class.BlogEntry.php");
include_once("class.BlogUser.php");

class BlogInfo {
    // private variables
    var $blogId; // blog_list.blog_id
    var $blogTitle; // blog_list.title
    var $blogTagline; //blog_list.tagline
    var $blogAdminUserId; // blog_list.admin
    var $blogAdminName; // blog_list.admin -> blog_users.name
    var $blogAdminEmail; // blog_list.admin -> blog_users.email
    var $blogAdminURL; // blog_list.admin -> blog_users.url
    var $blogUsers = array(); // list of BlogUser objects with access to this blog
    var $blogURL; // the url where this blog can be reached.
    var $blogTemplateId; // id of the template being used for this blog.
    var $blogEntries; // an array of entries for this blog. empty by default.
    var $blogType; // indicates whether the blog is public=1, protected=2, or private=3
    
    // constructor- used to create the BlogInfo instance
    // and populate it with information about the blog.
    function BlogInfo ($blogId) {
        global $db;
        global $baseurl;
        global $blogurl;

	if(is_numeric($blogId)) {
		
	        // general info.
	        $res = $db->Execute("select * from blog_list where blog_id=".escape($blogId));
	        $this->blogId = $blogId;
	        $this->blogTitle = $res->fields['title'];
		$this->blogTagline = $res->fields['tagline'];
	        $this->blogTemplateId = $res->fields['temp_id'];
	        $this->blogAdminUserId = $res->fields['admin'];
	        $blogTypeId = $res->fields['type_id'];
	        if ( $blogTypeId == '1' ) {
	            $this->blogType = 'public';
	        } elseif ( $blogTypeId == '2' ) {
	            $this->blogType = 'protected';
	        } else {
	            $this->blogType = 'private';
	        }

        	// list of authorized users.
	        $blogUsers = array();
	        $res = $db->Execute("select ba.user_id as user_id, ba.admin as admin, bu.login as login, bu.name as name, bu.email as email from blog_acl ba, blog_users bu where ba.blog_id=$blogId and ba.user_id = bu.id");
        	while (!$res->EOF) {
	            $blogUsers[] =& new BlogUser($res->fields['user_id'], $res->fields['login'],
	                                        $res->fields['email'], $res->fields['name'],
	                                        $res->fields['admin']);
            	    $res->MoveNext();
        	}
        	$this->blogUsers = $blogUsers;

	        // build the blog URL, assuming the demo.php page is
	        $this->blogURL = "$blogurl?blogid=$blogId";

	        // get the admin user info fields.
	        $sql = "select * from blog_users where id=$this->blogAdminUserId";
	        $rs = $db->Execute($sql);
	        $this->blogAdminName = $rs->fields['name'];
	        $this->blogAdminEmail = $rs->fields['email'];
	        $this->blogAdminURL = $rs->fields['url'];
	    }
    }

    // getters and setters
    function getBlogId() {
        return $this->blogId;
    }
    // no setter for blog_id, it is immutable.

    function getBlogTitle() {
        return $this->blogTitle;
    }
    function setBlogTitle($title) {
        global $db;
        $sql = "update blog_list set title='$title' where blog_id=$this->blogId";

        if ($db->Execute($sql) === true) {
            // the update was successful
            $this->blogTitle = $title;
        }
    }

	function getBlogTagline() {
        return $this->blogTagline;
    }
    function setBlogTagline($tag) {
        global $db;
        $sql = "update blog_list set tagline='$tag' where blog_id=$this->blogId";

        if ($db->Execute($sql) === true) {
            // the update was successful
            $this->blogTagline = $tag;
        }
    }

    function getBlogURL() {
        return $this->blogURL;
    }
    // no setter for blog URL, as there is no place to put it.
    // it would be nice to upgrade the blog_list table to include
    // the blog_url.   

    #function getLastUpdate() {
    #    return $this->lastUpdate;
    #}
    // no setter for last update.

    function getBlogTemplateId() {
        return $this->blogTemplateId;
    }
    
    // more full featured version...
    function getBlogTemplate() {
        global $db;
        $sql = "select template from blog_template where temp_id = $this->blogTemplateId";
        $rs = $db->Execute($sql);
        return $rs->fields['template'];
    }
    // no setter for blog template id.

    function getBlogAdminName() {
        return $this->blogAdminName;
    }
    function getBlogAdminEmail() {
        return $this->blogAdminEmail;
    }
    function getBlogAdminURL() {
        return $this->blogAdminURL;
    }

    function getBlogUsers() {
        return $this->blogUsers;
    }

    // return the timestamp when this blog was last updated.
    function getLastUpdate() {
        // last updated.
        global $db;
        $res = $db->Execute("select max(date) as date from blog_entries where blog_id = $this->blogId");
        return  date("r", strtotime($res->fields['date']));
    }

    // use this function to get a single numbered BlogEntry object
    // for this blog.
    function getBlogEntryById($entryId) {
        global $db;
        if ( !$this->isUserAuthorized() ) {
            return null;
        }

        // the sql to grab the speicific entry.
        $sql = "select * from blog_entries where blog_entry_id=$entryId and blog_id = $this->blogId";
        $rs = $db->Execute($sql);
        // may have zero entries. in that case, return null.
        if (!$rs) {
            // the result set is empty. return null.
            return NULL;
        } else {
            if (!$rs->EOF) {
                // create the new blog entry object...
                $blogEntry = new BlogEntry($rs);
            }
        }
        return $blogEntry;
    }

    // this will remove the blog entry. this will
    // perform any of the security checks necessary to ensure that the
    // user is authorized to remove the entry. It will return false
    // if there was an error trying to delete the entry.
    function deleteBlogEntryById($entryId) {
        // figure out who the currently logged in user is.
        $uid = getUID($_SESSION['login']);

        // retrieve the entry.
        $blogEntry = $this->getBlogEntryById($entryId);

        if (($uid == $blogEntry->entryUserId) or (isBlogAdmin($this->blogId)) or (isAdmin())) {
            // yes, they are authorized, so remove the entry.
            if ( $blogEntry->delete() ) {
                return true;
            }
        }
        // must not have worked...
        return false;
    }

    // this funciton will update the selected blog entry after performing
    // security checks to make sure the user is authorized to perform the update.
    function updateBlogEntryById($entryId, $title, $body, $formatId, $categoryId) {
        // figure out who the currently logged in user is.
        $uid = getUID($_SESSION['login']);

        $title = escape($title);
        $body = escape ($body);

        // retrieve the entry
        $blogEntry = $this->getBlogEntryById($entryId);
        if (($uid == $blogEntry->entryUserId) or (isBlogAdmin($this->blogId)) or (isAdmin())) {
            // yes, they are authorized, so remove the entry.
            if ( $blogEntry->update($title, $body, $formatId, $categoryId) ) {
                return true;

            }
        }
        // must not have worked...
        return false;

    }

    // this will return those blog entries that
    // match all of the criteria that were submitted. This is
    // primarily used by archive.php
    function getBlogEntriesByCriteria($keyword, $entryId, $categoryId, $date, $eid=0) {
        global $db;
        if ( !$this->isUserAuthorized() ) {
            return null;
        }

	$entryId = intval($entryId);
	$categoryId = intval($categoryId);
	$eid = intval($eid);

        $sql = "select * from blog_entries where blog_id = $this->blogId ";
        if ( !empty($keyword) ) {
        	$keylist = explode(' ',escape($keyword));
        	foreach($keylist as $key){
			$sql .= " and (title LIKE '%$key%' OR body LIKE '%$key%') ";
		}	
        }
        if ( !empty($entryId) ) {
            $sql .= " and blog_entry_id = $entryId ";
        } elseif($eid) {
   	    $sql .= " and compat_entry_id = $eid ";
	}
		
        if ( !empty($categoryId) ) {
            $sql .= " and cat_id = $categoryId ";
        }
        if ( !empty($date) ) {
            $sql .= " and date like '$date%' ";
        }
        $sql .= " order by blog_entry_id DESC ";

        $rs = $db->Execute($sql);
        if (!$rs) {
            // nothing in result set. return empty array.
            return array();
        } else {
            $blogEntries = array();
            while (!$rs->EOF) {
                #$blogEntry = new BlogEntry($rs, $this->blogTableName, $this->blogId);
                $blogEntry = new BlogEntry($rs);
                $blogEntries[] = $blogEntry;
                $rs->MoveNext();
            }
            return $blogEntries;
        }

    }
    
    #right now limit doesn't do anything - fix this later
    function getBlogEntriesByAuthorLogin($login, $cid ='', $limit = 0) {
        global $db;

	$cid = intval($cid);

        $sql = "select * from blog_entries, blog_users where blog_entries.blog_id = $this->blogId ";
        if ( !empty($login) ) {
            $sql .= " and login = '$login' and blog_users.id = blog_entries.userid";
        }
        if ( !empty($categoryId) ) {
            $sql .= " and cat_id = $categoryId ";
        }

        $sql .= " order by blog_entry_id DESC ";

        $rs = $db->Execute($sql);
        if (!$rs) {
            // nothing in result set. return empty array.
            return array();
        } else {
            $blogEntries = array();
            while (!$rs->EOF) {
                $blogEntry = new BlogEntry($rs);
                $blogEntries[] = $blogEntry;
                $rs->MoveNext();
            }
            return $blogEntries;
        }

    }
    // use this function to get the N most recent BlogEntry objects
    // for this blog
    function getLastNEntries($n) {
        return $this->getBlogEntriesByRange($n,0);
    }

    // use this function to get all blog entries in a date range (inclusive).
    // dates must be in 'Y-M-D h:m:s' format.
    function getEntriesByDate($startDate, $endDate) {
        global $db;
        if ( !$this->isUserAuthorized() ) {
            return null;
        }

        // use the PHP functions to convert this into the ISO date format
        // standard, just to be nice :)
        $startDate = strtotime($startDate);
        $endDate = strtotime($endDate);
        // then get them out properly formatted
        $startDate = strftime("%Y-%m-%d %H:%M:%S", $startDate);
        $endDate = strftime("%Y-%m-%d %H:%M:%S", $endDate);

        // use the adodb functions to convert these dates into something the DB will understand
        $dbStartDate = $db->DBTimeStamp($startDate);
        $dbEndDate = $db->DBTimeStamp($endDate);
        $sql = "select * from blog_entries where blog_id = $this->blogId and date >= $dbStartDate and date <= $dbEndDate";

        $uid = getUID($_SESSION['login']);
        if((!isBlogAdmin($this->blogId)) or (!isAdmin())) {
            $sql .= " AND userid=$uid ";
        }

        $rs = $db->Execute($sql);
        if (!$rs) {
            // nothing in result set. return empty array.
            return array();
        } else {
            $blogEntries = array();
            while (!$rs->EOF) {
                $blogEntry = new BlogEntry($rs);
                $blogEntries[] = $blogEntry;
                $rs->MoveNext();
            }
            return $blogEntries;
        }
    }

    // This function will return a list, in order, formatted as "YYYY-MM" for each year and month
    // in which this blog has entries. Used by the 'archive' block in blocks.php.
    function getYearMonthOfEntries() {
        global $db;

        $sql = "select date from blog_entries where blog_id = $this->blogId order by date asc";
        $res = $db->Execute($sql);
        $dateHash = array();
        while (!$res->EOF) {
            $date = $res->fields['date'];
            // convert to unix timestamp, for safety...
            $unixTS = $db->UnixTimeStamp($date);
            $truncDate = date("Y-m",$unixTS); // this will return 9999-99 for the date.
            $dateHash[$truncDate] = 1;

            $res->MoveNext();
        }

        return $dateHash;


    }

    // use this method to insert a new entry into the blog_entries table for
    // this blog. The entry id of the new blog entry will be returned if the
    // insertion is successful.
    function insertBlogEntry($title, $body, $userId, $formatId, $catId) {
        global $db;

		#$sql = "INSERT into blog_".$blogname." (id,title,body,date,userid,format,cat_id) VALUES ($id,'".escape($etitle)."','".escape($body)."',now(),$uid,$format,$cid)";
        // first, make sure the title and body are safe for insert.
        $title = escape($title);
        $body = escape ($body);

        // we need to generate the compat_entry_id for this blog_entries
        // before we do the insert. this sequence really needs to be
        // wrapped in a transaction to make it safe.
        $sql = "select max(compat_entry_id) as id from blog_entries where blog_id = $this->blogId";
        $res = $db->Execute($sql);
        $maxEntryId = $res->fields['id'];
        // the new compat id will be +1 on that...
        $compatEntryId = $maxEntryId + 1;

        // come up with a new timestamp to insert.
        $dateTime = strftime("%Y-%m-%d %H:%M:%S");

        // now insert the new entry.
		$sql = "insert into blog_entries (blog_id, compat_entry_id, body, post_date, date, userid, title,format, cat_id) values ($this->blogId, $compatEntryId, '$body', '$dateTime', '$dateTime', $userId, '$title', $formatId, $catId)";
	if ( $db->Execute($sql) === true ) {
            // the update was successful!
            return $compatEntryId;
        }

        return null;
    }

    function updateBlogTemplate($templateId) {
        global $db;

        $sql = "UPDATE blog_list set temp_id=$templateId where blog_id=$this->blogId";
        $db->Execute($sql);
        return true;
    }

    function getEntryCount() {
        global $db;

        $uid = getUID($_SESSION['login']);
        $sql = "select count(*) as count from blog_entries where blog_id = $this->blogId";
        if((!isBlogAdmin($this->blogId)) or (!isAdmin()) and (!empty($uid))) {
            $sql .= " AND userid=$uid ";
        }
        $res = $db->Execute($sql);
        return $res->fields['count'];
    }

    function getBlogEntriesByRange($limit, $start, $byUser = 0) {
        global $db;
        if ( !$this->isUserAuthorized() ) {
            return null;
        }

        $uid = getUID($_SESSION['login']);
        $sql = "select * from blog_entries where blog_id = $this->blogId";
		if($byUser) {
			if(!isAdmin() && !(isBlogAdmin($this->blogId) == 1)) {
				$sql .= " and userid=$uid";
			}
		}
        $sql .=" order by blog_entry_id desc";

        $rs = $db->SelectLimit($sql, $limit, $start);
        if (!$rs) {
            return array();
        } else {
            $blogEntries = array();
            while (!$rs->EOF) {
                $blogEntry = new BlogEntry($rs);
                $blogEntries[] = $blogEntry;
                $rs->MoveNext();
            }
            return $blogEntries;
        }

    }
    
    // method used to determine if the currently logged in user
    // is authorized to access entries from this blog. If the blog
    // is public, this will return immediately with true.
    // if the blog is protected, then it will return true as long as
    // the current user is logged in.
    // if the blog is private, then it will verify that the logged in
    // is in the ACL.
    function  isUserAuthorized() {
        $uid = getUID($_SESSION['login']);
        if ( $this->blogType == 'public' ) {
            return true;
        } elseif ( $this->blogType == 'protected ' ) {
            if ( isset ($_SESSION['login']) ) {
                return true;
            }
        } else {
            foreach ( $this->blogUsers as $blogUser ) {
                if ( $uid == $blogUser->userId ) {
                    return true;
                }
            }
        }
		#temporarily set to true to deal with possible incompatibilities between J. Buberel's changes and mine. (J. Hu 2/13/05)
        return true;
    }


}

?>

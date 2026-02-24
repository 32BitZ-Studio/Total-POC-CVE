<?php 

	/*******************************************************************
	 * $Id: class.BlogServer.php,v 1.4 2005/06/25 05:17:47 f-bomb Exp $
	 *
	 * class.BlogServer.php
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
	 * This class is meant to represent the overall BlogServer and to act
     * as a container of all of the blogs hosted on that server instance.
     * Initially, this will provide methods for retrieving the list of
     * BlogInfo objects for each of the blogs listed in the blog_list
     * table. There are also methods for adding and removing entrie blogs.
     *
     * To use BlogServer, you create a new instance using the provided
     * constructor:
     *  include_once("class.BlogServer.php");
     *  $myBlogServer = new BlogServer();
     *
	 */

include_once("lib.php");
include_once("class.BlogInfo.php");

class BlogServer {
    // private variables
    var $blogInfoList; // an array of $blogInfo objects.


    // constructor.
    function BlogServer () {
        global $db;
        
        // let's get the list of blogs_id's that we can pass to the constructor
        // of class.BlogInfo to generate our list of BlogInfo objects.
        $sql = "select blog_id from blog_list";
        $res = $db->Execute($sql);
        while (!$res->EOF) {
            $blogId = $res->fields['blog_id'];
            $blogInfoList[] =& new BlogInfo($blogId);
            $res->MoveNext();
        }


    }

    // getters and setters
    function &getBlogInfoList() {
        return $this->blogInfoList;
    }

    function getBlogInfoById($blogId) {

        foreach ($this->blogInfoList as $blogInfo) {
            if ($blogInfo->blogId == $blogId) {
                return $blogInfo;
            }
        }
        return NULL;
    }

    function &createBlog($blogTitle, $tagline, $type, $userList, $admin) {
		global $db;
        // this is so NOT transactionally correct!! FIXME.
        $sql = "select max(blog_id) as blog_id from blog_list";
        $res = $db->Execute($sql);
        $newBlogId = $res->fields['blog_id'] + 1;


        $sql = "insert into blog_list (blog_id,title,type_id,tagline,admin) values ($newBlogId,'".escape($blogTitle)."',$type,'".escape($tagline)."',$admin)";
        $res = $db->Execute($sql);

        $sql = "insert into blog_categories (cat_name,blog_id) values ('General',$newBlogId)";
        $res = $db->Execute($sql);

        foreach ($userList as $userId) {
            $sql = "insert into blog_acl (user_id,blog_id) values ($userId,$newBlogId)";
            $res = $db->Execute($sql);
        }

		$blogInfo =& new BlogInfo($newBlogId);

		return $blogInfo;
    }

    function deleteBlogById($blogId) {
	global $db;

	$sql = "select * from blog_entries where blog_id=$blogId";
	$rs = $db->Execute($sql);
	while (!$rs->EOF) {
		$sql = "delete from blog_trackback where entry_id=".$rs->fields['blog_entry_id'];
        	$res2 = $db->Execute($sql);

        	$sql = "delete from blog_pingback where entry_id=".$rs->fields['blog_entry_id'];
	        $res2 = $db->Execute($sql); 
                $rs->MoveNext();
        }

        $sql = "delete from blog_list where blog_id=$blogId";
        $res2 = $db->Execute($sql);

        $sql = "delete from blog_acl where blog_id=$blogId";
        $res2 = $db->Execute($sql);

        $sql = "delete from blog_entries where blog_id=$blogId";
        $res2 = $db->Execute($sql);

	$sql = "delete from blog_karma where bid=$blogId";
        $res2 = $db->Execute($sql);

	$sql = "delete from blog_comments where bid=$blogId";
        $res2 = $db->Execute($sql);

	$sql = "delete from blog_categories where blog_id=$blogId";
        $res2 = $db->Execute($sql);

	$sql = "delete from blog_blocks where blog_id=$blogId";
        $res2 = $db->Execute($sql);

    }

    // This should probably be conisdered deprecated, now that
    // blog data is primarily stored in the blog_entries table.
    function getBlogTableName() {
        return $this->blogTableName;
    }
    // no setter for table name.
    
    function getBlogURL() {
        return $this->blogURL;
    }
    // no setter for blog URL, as there is no place to put it.
    // it would be nice to upgrade the blog_list table to include
    // the blog_url.   

    function getLastUpdate() {
        return $this->lastUpdate;
    }
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
    #function getLastUpdate() {
        // last updated.
    #    global $db;
    #    $res = $db->Execute("select max(date) as date from blog_entries where blog_id = $blogId");
    #    return  date("r", strtotime($res->fields['date']));
    #}

    // use this function to get a single numbered BlogEntry object
    // for this blog.
    function getBlogEntryById($entryId) {
        global $db;
        // the sql to grab the speicific entry.
        $sql = "select * from blog_entries where compat_entry_id=$entryId and blog_id = $this->blogId";
        $rs = $db->Execute($sql);
        // may have zero entries. in that case, return null.
        if (!$rs) {
            // the result set is empty. return null.
            return null;
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
        $uid = getUID($HTTP_SESSION_VARS['login']);

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
        $uid = getUID($HTTP_SESSION_VARS['login']);

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
    function getBlogEntriesByCriteria($keyword, $entryId, $categoryId, $date) {
        global $db;

        $sql = "select * from blog_entries where blog_id = $this->blogId ";
        if ( !empty($keyword) ) {
            $sql .= " and (title LIKE '%$keyword%' OR body LIKE '%$keyword%') ";
        }
        if ( !empty($entryId) ) {
            $sql .= " and compat_entry_id = $entryId ";
        }
        if ( !empty($categoryId) ) {
            $sql .= " and cat_id = $categoryId ";
        }
        if ( !empty($date) ) {
            $sql .= " and date like '$date%' ";
        }
        $sql .= " order by compat_entry_id DESC ";

        $rs = $db->Execute($sql);
        if (!$rs) {
            // nothing in result set. return empty array.
            return array();
        } else {
            $blogEntries = array();
            while (!$rs->EOF) {
                $blogEntry = new BlogEntry($rs, $this->blogTableName, $this->blogId);
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

        $uid = getUID($HTTP_SESSION_VARS['login']);
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
                $blogEntry = new BlogEntry($rs, $this->blogTableName, $this->blogId);
                $blogEntries[] = $blogEntry;
                $rs->MoveNext();
            }
            return $blogEntries;
        }
    }

    // use this method to insert a new entry into the blog_entries table for
    // this blog.
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
        $sql = "insert into blog_entries (blog_id, compat_entry_id, body, date, userid, title,format, cat_id) values ($this->blogId, $compatEntryId, '$body', '$dateTime', $userId, '$title', $formatId, $catId)";
        if ( $db->Execute($sql) === true ) {
            // the update was successful!
            return true;
        }

        return false;
    }

    function updateBlogTemplate ($templateId) {
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

    function getBlogEntriesByRange($limit, $start) {
        global $db;

        $uid = getUID($_SESSION['login']);
        $sql = "select * from blog_entries where blog_id = $this->blogId ";
        $sql .=" order by date desc";

        $rs = $db->SelectLimit($sql, $limit, $start);
        if (!$rs) {
            return array();
        } else {
            $blogEntries = array();
            while (!$rs->EOF) {
                $blogEntry = new BlogEntry($rs, $this->blogTableName, $this->blogId);
                $blogEntries[] = $blogEntry;
                $rs->MoveNext();
            }
            return $blogEntries;
        }

    }

}

?>

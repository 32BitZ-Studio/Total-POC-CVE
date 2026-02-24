<?php 

	/*******************************************************************
	 * $Id: class.BlogEntry.php,v 1.4 2005/07/10 19:48:08 f-bomb Exp $
	 *
	 * class.BlogEntry.php
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
     * This class represents a single entry in a blog. Normally, you woun't
     * need to call the constructor directly...you would instead make use of
     * a BlogInfo object's entry retrieval methods in order to get an instance
     * of BlogEntry.
     *
     * Once you have the instance, you can access the member variables
     * directly for now (I have not made getters available yet).
     *
     * Ultimately, This class needs to be expanded to include a factory
     * method for the creation of new BlogEntries, as well as methods to
     * commit those new BlogEntries to the db. (->create(), ->save()).
	 */
include_once("lib.php");

class BlogEntry {
    // member variables
    var $entryId; //blog_entries.compat_entry_id
    var $entryBlogId; // blog_list.id
    var $entryBlogTabeName; // the table the blog entry came from.
    var $entryBody; //blog_name.body
    var $entryPostDate; //blog_name.post_date
    var $entryDate; //blog_name.date
    var $formattedEntryDate; //blog_name.date
    var $entryUserId; // blog_name.userid
    var $entryAuthorName; // blog_users.name
    var $entryAuthorEmail; // blog_users.email
    var $entryTitle; // blog_name.title
    var $entryKarma; // blog_name.karma
    var $entryFormat; // blog_name.format
    var $entryCategoryId; // blog_name.cat_id
    var $entryCategoryName; // blog_name.cat_id -> blog_categories.cat_id
    var $entryURL; // the archive URL to this blog entry.
    var $entryCommentsURL; // the url where comments for this item are stored.
    var $entryRSSURL; // the url of the RSS 0.91 feed containing this item.
    var $entryRSS2URL; // the url of the RSS 2.0 feed containing this item.


    // use variable names directly to access properties.
    // constructor that will build a new instance of the object
    // when given a reference to a result set object that points
    // to a row from the blog_name table.
    function BlogEntry($resultSet) {
        global $db;
        global $baseurl;
		global $dateformat;

#        $this->entryTableName = $tableName;
        $this->entryId = $resultSet->fields['blog_entry_id'];
        $this->entryBody = ereg_replace("<tick>","'",$resultSet->fields['body']);
	$this->entryPostDate = $resultSet->fields['post_date'];
        $this->formattedPostDate = date($dateformat, strtotime($resultSet->fields['post_date']));
	$this->entryDate = $resultSet->fields['date'];
        $this->formattedEntryDate = date($dateformat, strtotime($resultSet->fields['date']));
        $this->entryUserId = $resultSet->fields['userid'];
        $this->entryTitle = ereg_replace("<tick>","'",$resultSet->fields['title']);
        $this->entryKarma = $resultSet->fields['karma'];
        $this->entryFormat = $resultSet->fields['format'];
        $this->entryCategoryId = $resultSet->fields['cat_id'];

        // need to get the email address of the author.
        $sql="select * from blog_users where id=$this->entryUserId";
        $rs = $db->Execute($sql);
        $this->entryAuthorName = $rs->fields['name'];
        $this->entryAuthorEmail = $rs->fields['email'];

        // then the category
        $sql = "select * from blog_categories where cat_id=$this->entryCategoryId";
        $rs = $db->Execute($sql);
        $this->entryCategoryName = $rs->fields['cat_name'];

        // the blog id.
        $this->entryBlogId = $resultSet->fields['blog_id'];
    
        // configure the URL for this entry
        $this->entryURL = "$baseurl/archive.php?blogid=$this->entryBlogId&pid=$this->entryId";

        // then the comments URL...
        $this->entryCommentsURL = "$baseurl/comments.php?blogid=$this->entryBlogId&pid=$this->entryId";

        // and then the source URL (points to the RSS feed containing this item)
        $this->entryRSSURL = "$baseurl/rss.php?blogid=$this->entryBlogId";
        $this->entryRSS2URL = "$baseurl/rss2.php?blogid=$this->entryBlogId";
    }

    function delete() {
        global $db;

        $sql = "delete from blog_entries where blog_id = $this->entryBlogId and blog_entry_id = $this->entryId";
        $db->Execute($sql);
        return true;
    }

    function update ($title, $body, $formatId, $categoryId) {
        global $db;

        // generate the modification date
        $updateDate = strftime("%Y-%m-%d %H:%M:%S");

        $sql = "update blog_entries set body = '$body', title = '$title', date = '$updateDate', format = $formatId, cat_id = $categoryId  where blog_id = $this->entryBlogId and blog_entry_id = $this->entryId";
        $db->Execute($sql);
        return true;
    }

    function getCommentCount() {
        global $db;

        $sql = "select count(*) as count from blog_comments where bid='$this->entryBlogId' and eid='$this->entryId'";
        $res = $db->Execute($sql);
        return $res->fields['count'];
    }

    function getCmntLink($useCommentWindow, $templateId) {
        global $baseurl;

        if($useCommentWindow) {
            $href= "javascript: openComments('$baseurl','$this->entryBlogId','$this->entryId','$templateId');";
        } else {
            $href = "$this->entryCommentsURL";
        }

        $str = "<a href=\"$href\">";

        #get number of comments from DB
        $commentCount = $this->getCommentCount();

        if($commentCount == 0) {
            $str .= "comments?";
        } else {
            $str .= $commentCount." comments";
        }

        $str .= "</a>";

        return $str;
    }

    function getFormattedKarmaLink() {

        global $ratename,  $baseurl;

        $str = "$ratename: ";
        $str .= $this->entryKarma." ( <a href=\"$baseurl/karma.php?op=add&blogid=$this->entryBlogId&pid=$this->entryId\">+</a> / <a href=\"$baseurl/karma.php?op=sub&blogid=$this->entryBlogId&pid=$this->entryId\">-</a> )";

        return $str;
    }

    function getFormattedCategoryLink() {
        return "<a href=\"archive.php?blogid=$this->entryBlogId&cid=$this->entryCategoryId\">".$this->entryCategoryName."</a>";
    }

    function getFormattedEntryLink() {
        $str = "<a href=\"$this->entryURL\">permalink</a>";
        return $str;
    }

}

?>

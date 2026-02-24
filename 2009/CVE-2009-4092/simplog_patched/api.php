<?php 
/* 
 * $Id: api.php,v 1.3 2006/04/13 17:41:02 f-bomb Exp $
 *
 * api.php
 * Implements the Blogger and metaWeblog APIs for MyPHPBlog
 * Created by Dougal Campbell <dougal@gunters.org>, <emc3@users.sf.net>
 *	http://dougal.gunters.org/
 *
 * License: GPL
 *
 * NOTES:
 *	Info about the Blogger API: 
 *		http://plant.blogger.com/api/
 *
 *	More info (bloggerDev mailing list): 
 *		http://groups.yahoo.com/group/bloggerDev
 *
 *	Info about the metaWeblog API:
 *		http://www.xmlrpc.com/discuss/msgReader$2198?mode=topic
 *
 *	The Blogger API doesn't support titles on posts. This module follows
 *	the convention of using '<title>foo</title>' at the beginning of a
 *	post to denote the title. Some clients (e.g., w.bloggar version 3)
 *	support this automagically.
 *
 *	MyPHPBlog doesn't currently have a way to store a unique URL
 *	for each blogid. Because of this, the getUsersBlogs method 
 *	will use the global $blogurl for all blogs. This will affect
 *	you if you have multiple blogs, each with a unique URL. In the
 *	future, we might want to add a URL field to the blog_list table.
 *
 *	Blogger uses unique post ids, across multiple blogs. MyPHPBlog
 *	post ids are only unique within their blog (there is an argument
 *	to be made here that MyPHPBlog's design is stronger, in that 
 *	respect). Because of that, this module internally combines
 *	the blogid and postid (separated by a colon). This shouldn't 
 *	affect anything visibly, but I wanted to note it here so that
 *	others will understand what's going on in the relevant functions.
 *
 *	The API functions related to templates have no comparable functions
 *	in MyPHPBlog. Unimplemented functions will be intercepted by this
 *	module, however, and will return an appropriate error message.
 *
 * $Log: api.php,v $
 * Revision 1.3  2006/04/13 17:41:02  f-bomb
 * renamed functiont o resolve name conflict
 *
 * Revision 1.2  2004/02/06 07:57:14  f-bomb
 * changes for 0.9beta
 *
 * Revision 1.6  2003/10/09 06:47:07  f-bomb
 * added pingback functionality
 *
 * Revision 1.5  2003/08/06 06:05:04  jbuberel
 * Big schema creation and related overhaul, plus updates to the install and upgrade procedures.
 *
 * Known remaining bug: Template previewing is broken.
 *
 * Other bugs to be discovered.
 *
 * Revision 1.4  2003/03/13 17:33:07  emc3
 * Updated for 0.8
 *
 * Revision 1.3  2002/10/24 14:04:54  emc3
 * Declared $title and $blogurl as globals so that the weblogs.com ping function would work correctly
 *
 * Revision 1.2  2002/10/24 13:58:54  emc3
 * Declared $use_weblog_rpc as a global so that the weblogs.com ping function would work correctly
 *
 * Revision 1.1  2002/09/27 14:07:48  emc3
 * New file for Blogger and metaWeblog APIs
 *
 *
 */

// Pull in the MyPHPBlog lib for some useful globals and functions
include_once('lib.php');

// Pull in the XML-RPC libraries from Useful, Inc.
//   http://usefulinc.com/
include_once('xmlrpc.inc');
include_once('xmlrpcs.inc');
include_once('class.BlogInfo.php');
include_once('class.BlogEntry.php');
include_once('class.BlogUser.php');

/***********************************
 *
 * Define API and helper functions
 *
 ***********************************/

// First, the Blogger API stuff:

function newPost ($params) {	// ($appkey, $blogid, $user, $pass, $content, $publish) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xblogid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	$xcontent = $params->getParam(4);
	$xpublish = $params->getParam(5);
	
	$appkey = $xappkey->scalarval();
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$content = $xcontent->scalarval();
	$publish = $xpublish->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff
		if (!mpb_user_blog_check($uid,$blogid)) {
			$err = "User " . $user . " does not have access to blogid " . $blogid;
		}

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		// MyPHPBlog's organization is different from Blogger. We
		// have to play a few tricks with postid, because it is 
		// not unique throughout the system, but instead is only
		// unique to a particular blogid. We separate the blogid
		// and postid with a colon, and pass that value to the
		// client.

		// Use the first line of the post as the title
		//list($title,$content) = explode("\n",$content,2);

		// Let's try using <title> tags....
		$result = preg_match('/<title>(.+)<\/title>(.*)/is',$content,$arr);
		if ($result) {
			$title = $arr[1];
			$body = $arr[2];
		} else {
			$title = '';
			$body = $content;
		}

		$postid = mpb_new_post($uid,$blogid,$title,$body);
		$postid = $blogid . ':' . $postid;
		
		$myResp = new xmlrpcval($postid,"string");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

function editPost ($params) {	// ($appkey, $postid, $user, $pass, $content, $publish) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xpostid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	$xcontent = $params->getParam(4);
	$xpublish = $params->getParam(5);
	
	$appkey = $xappkey->scalarval();
	$postid = $xpostid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$content = $xcontent->scalarval();
	$publish = $xpublish->scalarval();

	// MyPHPBlog's organization is different from Blogger. We
	// have to play a few tricks with postid, because it is 
	// not unique throughout the system, but instead is only
	// unique to a particular blogid. We separate the blogid
	// and postid with a colon, and pass that value to the
	// client.
	list($blogid,$postid) = explode(':',$postid);

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff
		if (!mpb_user_blog_check($uid,$blogid)) {
			$err = "User $user does not have post access for blogid $blogid";
		}
		if (!mpb_user_post_check($uid,$blogid,$postid)) {
			$err = "User $user cannot edit postid $postid";
		}
	} else {
		// Bad login
		$err = $login['err'];
	}

	//$err = "editPost not implemented yet";
	
	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.

		// Let's try using <title> tags....
		$result = preg_match('/^<title>(.+)<\/title>(.*)/is',$content,$arr);
		if ($result) {
			$title = $arr[1];
			$body = $arr[2];
		} else {
			$title = '';
			$body = $content;
		}

		mpb_update_post($uid,$blogid,$postid,$title,$body);
		
		$myResp = new xmlrpcval(1,"boolean");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

function getPost ($params) {	// ($appkey, $postid, $user, $pass) 
	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xpostid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	
	$appkey = $xappkey->scalarval();
	$bpostid = $xpostid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();

	list($blogid,$postid) = explode(':',$bpostid);

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		$xmlrpcpost = mpb_get_post($blogid,$postid);

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		$myResp = new xmlrpcval($xmlrpcpost,"struct");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function deletePost ($params) {	// ($appkey, $postid, $user, $pass, $publish) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xpostid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	$xpublish = $params->getParam(4);
	
	$appkey = $xappkey->scalarval();
	$postid = $xpostid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$publish = $xpublish->scalarval();

	// MyPHPBlog's organization is different from Blogger. We
	// have to play a few tricks with postid, because it is 
	// not unique throughout the system, but instead is only
	// unique to a particular blogid. We separate the blogid
	// and postid with a colon, and pass that value to the
	// client.
	list($blogid,$postid) = explode(':',$postid);

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// do some stuff
		if (!mpb_user_post_check($uid,$blogid,$postid)) {
			$err = "User $user cannot delete post $postid from blogid $blogid";
		}
	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		mpb_delete_post($blogid,$postid);
		
		$myResp = new xmlrpcval(1,"boolean");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function getRecentPosts ($params) {	// ($appkey, $blogid, $user, $pass, $num) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xblogid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	$xnum = $params->getParam(4);
	
	$appkey = $xappkey->scalarval();
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$num = $xnum->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Make sure this user has access to the blog specified:
		if (mpb_user_blog_check($uid,$blogid)) {
			$postlist = mpb_recent($blogid,$num);
		} else {
			$err = "User " . $user . " does not have access to blogid " . $blogid;
		}

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet. We can't just use xmlrpc_encode,
		// because of the datecreate field, which must be a date type.
		
		// Encode each entry of the array.
		foreach($postlist as $entry) {
			// convert the date
			$unixtime = strtotime($entry['datetime']);
			$isoString=iso8601_encode($unixtime);
			$date = new xmlrpcval($isoString,"dateTime.iso8601");
			$userid = new xmlrpcval($entry['userid']);
			$postid = new xmlrpcval($entry['postid']);
			$content = new xmlrpcval($entry['content']);

			$encode_arr = array(
				'datecreated' => $date,
				'userid' => $userid,
				'postid' => $postid,
				'content' => $content
			);
			
			$xmlrpcpostarr[] = new xmlrpcval($encode_arr,"struct");
		}	

		// Now convert that to an xmlrpc array type
		$myResp = new xmlrpcval($xmlrpcpostarr,"array");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function getUsersInfo ($params) {	// ($appkey, $user, $pass) 
	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	
	$appkey = $xappkey->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// do some stuff
	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		$xmlrpcuser = mpb_user_info($uid);
				
		$myResp = xmlrpc_encode($xmlrpcuser);

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function getUsersBlogs ($params) {	// ($appkey, $user, $pass)
	global $xmlrpcerruser;
	
	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	
	$appkey = $xappkey->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Get blog list for that uid:
		$bloglist = mpb_get_user_blogs($uid);
				
		if (!is_array($bloglist)) {
			$err = "User " . $user . " has no blogs.";
		}

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		// First, make a new array, encoded
		foreach($bloglist as $entry) {
			$xmlrpcblogarr[] = xmlrpc_encode($entry);
		}	

		// Now convert that to an xmlrpc array type
		$myResp = new xmlrpcval($xmlrpcblogarr,"array");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

function getTemplate ($params) {	// ($appkey, $blogid, $user, $pass, $type) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xblogid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	$xtype = $params->getParam(4);
	
	$appkey = $xappkey->scalarval();
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$type = $xtype->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff

	} else {
		// Bad login
		$err = $login['err'];
	}

	$err = "getTemplate not implemented yet";
	
	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		$myResp = new xmlrpcval("getTemplate not implemented yet","string");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

function setTemplate ($params) {	// ($appkey, $blogid, $user, $pass, $template, $type) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xappkey = $params->getParam(0);
	$xblogid = $params->getParam(1);
	$xuser = $params->getParam(2);
	$xpass = $params->getParam(3);
	$xtemplate = $params->getParam(4);
	$xtype = $params->getParam(5);
	
	$appkey = $xappkey->scalarval();
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$template = $xtemplate->scalarval();
	$type = $xtype->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff

	} else {
		// Bad login
		$err = $login['err'];
	}

	$err = "setTemplate not implemented yet";
	
	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		$myResp = new xmlrpcval(0,"boolean");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

/**********************
 *
 * metaWeblog API extensions
 *
 **********************/

function mw_newPost($params) {
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xblogid = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	$xcontent = $params->getParam(3);
	$xpublish = $params->getParam(4);
	
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$contentstruct = xmlrpc_decode($xcontent);
	$publish = $xpublish->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff
		if (!mpb_user_blog_check($uid,$blogid)) {
			$err = "User " . $user . " does not have access to blogid " . $blogid;
		}

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		// MyPHPBlog's organization is different from Blogger. We
		// have to play a few tricks with postid, because it is 
		// not unique throughout the system, but instead is only
		// unique to a particular blogid. We separate the blogid
		// and postid with a colon, and pass that value to the
		// client.

		$title = $contentstruct['title'];
		$content = $contentstruct['description'];
		$categories = $contentstruct['categories'];
		$cat_name = $categories[0];
		$cat_id = mpb_category_id($blogid,$cat_name);

		$postid = mpb_new_post($uid,$blogid,$title,$content,$cat_id);
		$postid = $blogid . ':' . $postid;
		
		$myResp = new xmlrpcval($postid,"string");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function mw_editPost ($params) {	// ($postid, $user, $pass, $content, $publish) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xpostid = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	$xcontent = $params->getParam(3);
	$xpublish = $params->getParam(4);
	
	$postid = $xpostid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$contentstruct = xmlrpc_decode($xcontent);
	$publish = $xpublish->scalarval();

	// MyPHPBlog's organization is different from Blogger. We
	// have to play a few tricks with postid, because it is 
	// not unique throughout the system, but instead is only
	// unique to a particular blogid. We separate the blogid
	// and postid with a colon, and pass that value to the
	// client.
	list($blogid,$postid) = explode(':',$postid);

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff
		if (!mpb_user_blog_check($uid,$blogid)) {
			$err = "User $user does not have post access for blogid $blogid";
		}
		if (!mpb_user_post_check($uid,$blogid,$postid)) {
			$err = "User $user cannot edit postid $postid";
		}
	} else {
		// Bad login
		$err = $login['err'];
	}

	//$err = "editPost not implemented yet";
	
	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.

		$title = $contentstruct['title'];
		$content = $contentstruct['description'];
		$categories = $contentstruct['categories'];
		$cat_name = $categories[0];
		$cat_id = mpb_category_id($blogid,$cat_name);

		mpb_update_post($uid,$blogid,$postid,$title,$content,$cat_id);
		
		$myResp = new xmlrpcval(1,"boolean");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

function mw_getPost ($params) {	// ($postid, $user, $pass) 
	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xpostid = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	
	$bpostid = $xpostid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();

	list($blogid, $postid) = explode(':',$bpostid);

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];

	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// do some stuff
		$xmlrpcpost = mpb_get_post($blogid,$postid);
		if ($xmlrpcpost['err']) {
			$err = $xmlrpcpost['err'];
		}

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		// Can't just use xmlrpc_encode here anymore, because
		// categories is an XML-RPC array data type, and the
		// xmlrpc_encode fuction will encode it as a struct.
		$myResp = xmlrpc_encode($xmlrpcpost);

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function mw_getRecentPosts ($params) {	// ($blogid, $user, $pass, $num) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xblogid = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	$xnum = $params->getParam(3);
	
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();
	$num = $xnum->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Make sure this user has access to the blog specified:
		if (mpb_user_blog_check($uid,$blogid)) {
			$postlist = mpb_recent($blogid,$num);
		} else {
			$err = "User " . $user . " does not have access to blogid " . $blogid;
		}

	} else {
		// Bad login
		$err = $login['err'];
	}

	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet. We can't just use xmlrpc_encode,
		// because of the datecreate field, which must be a date type.
		
		// Encode each entry of the array.
		foreach($postlist as $entry) {
			// convert the date
			$unixtime = strtotime($entry['datetime']);
			$isoString=iso8601_encode($unixtime);
			$date = new xmlrpcval($isoString,"dateTime.iso8601");
			$userid = new xmlrpcval($entry['userid']);
			$content = new xmlrpcval($entry['content']);

			$postid = new xmlrpcval($entry['postid']);
			$title = new xmlrpcval($entry['title']);
			$description = new xmlrpcval($entry['description']);
			$link = new xmlrpcval($entry['link']);
			$permalink = new xmlrpcval($entry['permalink']);
			$category = new xmlrpcval($entry['category']);
			$cat_arr = new xmlrpcval($category,'array');

			$encode_arr = array(
				'datecreated' => $date,
				'userid' => $userid,
				'postid' => $postid,
				'title' => $title,
				'description' => $description,
				'link' => $link,
				'permalink' => $permalink,
				'categories' => $cat_arr,
			);
			
			$xmlrpcpostarr[] = new xmlrpcval($encode_arr,"struct");
		}	

		// Now convert that to an xmlrpc array type
		$myResp = new xmlrpcval($xmlrpcpostarr,"array");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}

}

function mw_getCategories ($params) {	// ($blogid, $user, $pass) 
	global $xmlrpcerruser;

	// PHP makes us do this decode in multiple steps, with 
	// temp variables... It can't do something like:
	//    $foo = $params->getParam(0)->scalarval()

	$xblogid = $params->getParam(0);
	$xuser = $params->getParam(1);
	$xpass = $params->getParam(2);
	
	$blogid = $xblogid->scalarval();
	$user = $xuser->scalarval();
	$pass = $xpass->scalarval();

	// Check login
	$login = mpb_get_userid($user,$pass);

	$uid = $login['uid'];
	
	// uid of -1 means user/pass didn't jive
	if ($uid != -1) {
		// Do some stuff

	} else {
		// Bad login
		$err = $login['err'];
	}

	//$err = "metaWeblog.getCategories not implemented yet";
	
	if ($err) {
		// this is an error condition
		return new xmlrpcresp(0, $xmlrpcerruser+1, // user error 1
		$err);
	} else {
		// Build response packet.
		
		$categories = array();
		$resp = array();

		$categories = mpb_get_categories($blogid);
		for($i=0; $i<sizeof($categories); $i++) {
			$xrow = xmlrpc_encode($categories[$i]);
			
			$resp[] = $xrow;
		}

		$myResp = new xmlrpcval($resp,"array");

		// this is a successful value being returned
		return new xmlrpcresp($myResp);
	}
}

/**********************
 *
 * MyPHPBlog interaction functions
 *
 **********************/

// Check username and password. Return an array with the status:
// [ uid => mpb user id (-1 if failure),
//   err => error message if error occurs]
function mpb_get_userid($user,$pass) {
	global $db, $conn;
	$result = array('uid' => -1); // default value, no user

	// Encrypt the password for comparison to the db
	$enc = md5($pass);

	$mysql = "SELECT * from blog_users where login='" . $user;
	$mysql = $mysql."' AND password='$enc'";

	$res = $db->Execute($mysql);

	if($res->fields['login'] == $user) {
		// Valid login. Get the user's id.
		$result['uid'] = $res->fields['id'];
	} else {
		// Bad login
		$result['err'] = "Bad username or password.";
	}

	return $result;
}

// Given a userid, return a list of blogs that the user has access to
function mpb_get_user_blogs($uid) {
	global $db, $conn, $blogurl;
	
	// Get blog list for that uid:
	$sql = "SELECT blog_id from blog_acl where user_id=$uid order by blog_id";
	$res = $db->Execute($sql);
	while (!$res->EOF) {
		$sql2 = "SELECT title from blog_list where blog_id=".$res->fields['blog_id'];
		$res2 = $db->Execute($sql2);
		
		// We fudge a little here. MyPHPBlog doesn't keep an internal
		// concept of a separate URL for each blog. We just use the
		// global variable for all blogs.
		$result[] = array(
			"blogid" => $res->fields['blog_id'], 
			"blogName" => $res2->fields['title'], 
			"url" => $blogurl
		);
		
		$res->MoveNext();
	}
	
	return $result;
}

// Given a userid and blodid, check blog_acl
// Return true if user has access to that blog
function mpb_user_blog_check($uid,$blogid) {
	global $db, $conn;
	
	// Get blog list for that uid:
	$sql = "SELECT user_id, blog_id from blog_acl where user_id=$uid AND blog_id=$blogid";
	$res = $db->Execute($sql);
	
	if ($res->EOF) {
		$result = 0;
	} else {
		$result = 1;
	}
		
	return $result;
}

// Given a userid, blogid, and postid,
// Return true if user has access to that post
function mpb_user_post_check($uid,$blogid,$postid) {
	global $db, $conn;
	
	// Get blog list for that uid:
	$sql = "SELECT user_id, blog_id, admin from blog_acl where user_id=$uid AND blog_id=$blogid";
	$res = $db->Execute($sql);
	
	if ($res->EOF) {
		// User doesn't have access to the blog.
		return 0;
	} else if ($res->fields['admin'] == 'Y') {
		// User is admin for the blog -- access to all posts
		return 1;
	}

	$blogname = mpb_blog_name($blogid);
	
	// Check the postid in the blog, make sure that this is
	// the posting user:
	$sql = "SELECT userid from blog_".$blogname." where id=$postid";
	$res = $db->Execute($sql);
	
	if($uid == $res->fields['userid']) {
		$result = 1;
	} else {
		$result = 0;
	}
		
	return $result;
}

function mpb_recent($blogid,$num) {
	global $db, $conn, $baseurl;
	
	// I'll sneak this in here, in case any Blogger clients support it
	if ($num == -1) {
		$num = 99999; // Get all posts if num is -1
	}	
	
	$blogInfo =& new BlogInfo($blogid);
	$blogEntries = $blogInfo->getLastNEntries($num);

	foreach ($blogEntries as $blogEntry) {
		// Do tick replacement
		$body = ereg_replace("<tick>","'",$blogEntry->entryBody);
		$title = ereg_replace("<tick>","'",$blogEntry->entryTitle);
		$datetime = $res->entryDate;
		$iso_date = ereg_replace('[- ]','',$blogEntry->entryDate);
		
		// This seems to placate windows-based clients.
		$body = ereg_replace("\n","\r\n",$body);
		
		// Piece the title and body together, since Blogger doesn't
		// support titles.
		$content = '<category>' . $category . '</category>' . $body;
		$content = '<title>' . $title . '</title>' . $content;
		
		// Add an entry to the results array
		$result[] = array(
			'datetime' => $datetime,
			'userid' => $blogEntry->entryUserId,
			'postid' => $blogid . ':' . $blogEntry->entryId,
			'content' => $content,
			'title' => $title,
			'description' => $body,
			'link' => $baseurl . '/comments.php?blogid='.$blogid.'&eid='.$blogEntry->entryId,
			'permalink' => $baseurl . '/comments.php?blogid='.$blogid.'&eid='.$blogEntry->entryId,
			'categories' => array($blogEntry->entryCategoryName)
		);
		
		$res->MoveNext();
	}
	
	return $result;
}

function mpb_get_post($blogid,$postid) {
	global $db, $conn, $baseurl;
	
	// Borrowed/modified from blog.php:
	$blogInfo =& new BlogInfo($blogid);
    $blogEntry = $blogInfo->getBlogEntryById($postid);

	if (is_null($blogEntry)) {
		return array('err' => 'Postid '.$postid.' not found in blog '.$blogid.'.');
	}

	// Do tick replacement
	$body = ereg_replace("<tick>","'",$blogEntry->entryBody;);
	$title = ereg_replace("<tick>","'",$blogEntry->entryTitle);
	$datetime = $blogEntry->entryDate;
	$iso_date = ereg_replace('[- ]','',$datetime);
		
	// This seems to placate windows-based clients.
	$body = ereg_replace("\n","\r\n",$body);
		
	// Piece the title and body together, since Blogger doesn't
	// support titles.
	$content = $title . "\r\n" . $body;
	
	$cat_name = $blogEntry->entryCategoryName;
		
	// Put the results into an associative array. We should be
	// able to just use the same results for both Blogger and 
	// metaWeblog APIs, and they'll just pick out the elements
	// they want.
	$result = array(
		'link' => get_simple_link($postid),
		'title' => $title,
		'description' => $body,
		'datetime' => $datetime,
		'userid' => $blogEntry->entryUserId,
		'postid' => $blogid . ':' . $blogEntry->entryId,
		'content' => $content,
		'permalink' => $baseurl . '/comments.php?blogid='.$blogid.'&pid='.$blogEntry->entryId,
		'categories' => array($cat_name),
	);
		
	return $result;
}

// Get blog name from blogid
function mpb_blog_name($blogid) {
	global $db,$conn;
	
	$blogInfo =& new BlogInfo($blogid);


	return $blogInfo->getBlogTitle();
}

function mpb_new_post($uid,$blogid,$title,$body,$cat_id) {
		global $db,$conn,$use_weblog_rpc,$blogurl;
		
		$blogname = mpb_blog_name($blogid);
		
		$sql = "SELECT max(id) as id from blog_".$blogname;
		 
		$res = $db->Execute($sql);

		$id = $res->fields['id'] + 1;

		if(!$cat_id) { $cat_id = 1; }

		$body = ereg_replace("'","<tick>",$body);
		$title = ereg_replace("'","<tick>",$title);

		$sql = "INSERT into blog_".$blogname." (id,title,body,date,userid,cat_id) VALUES ($id,'$title','$body',now(),$uid,$cat_id)";

		$res = $db->Execute($sql);

		if ($use_weblog_rpc) {
			include("weblogrpc.php");
		}

		return $id;	
}

function mpb_update_post($uid,$blogid,$postid,$title,$content,$cat_id=1) {
		global $db,$conn,$use_weblog_rpc,$blogurl;
		
		$blogname = mpb_blog_name($blogid);
		
		$content = ereg_replace("'","<tick>",$content);
		$title = ereg_replace("'","<tick>",$title);

		$id = $res->fields['id'] + 1;

		if(!$cat_id) { $cat_id = 1; }

		$sql = "UPDATE blog_".$blogname." set title='$title',body='$content',cat_id=$cat_id where id=$postid";
		$res = $db->Execute($sql);
		
		if ($use_weblog_rpc) {
			include("weblogrpc.php");
		}
}

function mpb_delete_post($blogid,$postid) {
	global $db,$conn,$use_weblog_rpc,$title,$blogurl;
	
	$blogname = mpb_blog_name($blogid);
	
	$sql = "DELETE from blog_".$blogname." where id=$postid";
	$res = $db->Execute($sql);

	if ($use_weblog_rpc) {
		include("weblogrpc.php");
	}

}

function mpb_user_info($uid) {
	global $db,$conn;
	
	$sql = "SELECT * from blog_users WHERE id = $uid";
	$res = $db->Execute($sql);

	$info = array(	
	'userid' => $uid,
	'firstname' => '',
	'lastname' => '',
	'nickname' => $res->fields['name'],
	'email' => $res->fields['email'],
	'url' => $res->fields['url']
	);

	return $info;
}

function mpb_category_name($blogid, $cat_id=1) {
	global $db,$conn;
	
	$sql = "SELECT * from blog_categories WHERE blog_id = $blogid AND cat_id = $cat_id";
	$res = $db->Execute($sql);

	$info = $res->fields['cat_name'];

	return $info;
}

function mpb_category_id($blogid, $cat_name='General') {
	global $db,$conn;
	
	$sql = "SELECT * from blog_categories WHERE blog_id = $blogid AND cat_name = '$cat_name'";
	$res = $db->Execute($sql);

	$info = $res->fields['cat_id'];

	return $info;
}

function mpb_get_categories($blogid) {
	global $db,$conn,$baseurl;


	$db->SetFetchMode(ADODB_FETCH_ASSOC);
	$sql = "SELECT cat_id,cat_name AS description from blog_categories WHERE blog_id = $blogid";
	$res = $db->Execute($sql);
	
	// Make an associative array
	$categories = array();
	
	while ($row = $res->FetchRow()) {
		$htmlurl = $baseurl . "archive.php?blogid=$blogid&cid=" . $row['cat_id'];
		$row['htmlUrl'] = $htmlurl;
		$row['rssUrl'] = '';
		$categories[] = $row;
	}
	
	// Return the values
	return $categories;
}

#
# pingback_ping
#
# derived from pingback server used in b2evolution
#

function pingback_ping($m) {

	global $enable_pingback, $db;

    if (!$enable_pingback) {
        return new xmlrpcresp(new xmlrpcval('Pingback not enabled for this blog','string'));
    }
	$file = "debug.log";

    $linkfrom = $m->getParam(0);
    $linkfrom = $linkfrom->scalarval();

    $linkto = $m->getParam(1);
    $linkto = $linkto->scalarval();

    $messages = array(
        htmlentities("Pingback from ".$linkfrom." to ".$linkto." received.  Thanks for pointing to us"),
        htmlentities("Can't find the URL to the post you are trying to link to in your entry. Please check how you wrote the post's permalink in your entry."),
        htmlentities("You have already linked to this post from that entry.  thanks anyway."),
		htmlentities("We can't find the link in your post anywhere.  You can't pingback without linking to us."),
		
    );

    $message = $messages[0];

	#$linkto = unhtmlentities($linkto);
	#$linkfrom = unhtmlentities($linfrom);

    // Check if the page linked to is in our site
	$local = parse_url($linkto);
	if(preg_match("/blogid=(\d+)\&pid=(\d+)/",$local['query'],$m)) {
		$blogid = $m[1];
		$pid = $m[2];
        // let's find which post is linked to
		$sql = "SELECT * from blog_entries where blog_id=$blogid and blog_entry_id=$pid";
		$r = $db->Execute($sql);

		if($r->RecordCount() > 0) {			
            // check that the remote site didn't already pingback this entry
			$sql = "SELECT * from blog_pingback where entry_id=$pid and url='$linkfrom'";
			$r = $db->Execute($sql);
			if($r->RecordCount() <1) {
                // Let's check the remote site
				include("class.HttpClient.php");

				$contents = HttpClient::quickGet($linkfrom);
				$contents = unhtmlentities($contents);
				#$contents = strip_tags($contents,'<title><a>');
				if(strpos($contents,$linkto)) {
					//find title
					if(preg_match("/<title>(.*?)<\/title>/",$contents,$m)) {
						$title = $m[1];
					} else {
						$title = $linkfrom;
					}

					//grab excerpt -- not implemented yet
					$excerpt = '';

					//insert pingback into DB
					$sql = "INSERT into blog_pingback (entry_id,url,title,excerpt,blog_name,added) values ($pid,'$linkfrom','$title','$excerpt','$title',now())";
					$r = $db->Execute($sql);
					
				} else {
					$message = $messages[3];
				}
			} else {
				$message = $messages[2];
			}
		} else { 
			$message = $messages[1];
		}
	} else {
		$message = $messages[1];
	}
            // Post_ID not found
    return new xmlrpcresp(new xmlrpcval($message,'string'));
}










/*******************************
 * 
 *         Main code
 *
 *******************************/
 
// Set up XML-RPC server instance
$s=new xmlrpc_server( 
	array(	"blogger.newPost" =>
			array("function" => "newPost",
				"signature" => array(array($xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcBoolean)),
				"doc" => "Make a new post to the weblog"
			),
			"blogger.editPost" =>
			array("function" => "editPost",
				"signature" => array(array($xmlrpcBoolean,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcBoolean)),
				"doc" => "Edit a posting"
			),
			"blogger.deletePost" =>
			array("function" => "deletePost",
				"signature" => array(array($xmlrpcBoolean,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcBoolean)),
				"doc" => "Delete a posting"
			),
			"blogger.getUsersBlogs" =>
			array("function" => "getUsersBlogs",
				"signature" => array(array($xmlrpcArray,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Get a list of blogs for a user"
			),
			"blogger.getUserInfo" =>
			array("function" => "getUsersInfo",
				"signature" => array(array($xmlrpcStruct,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Get a list of blogs for a user"
			),
			"blogger.getTemplate" =>
			array("function" => "getTemplate",
				"signature" => array(array($xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Get a template. Not implemented for MyPHPBlog."
			),
			"blogger.setTemplate" =>
			array("function" => "setTemplate",
				"signature" => array(array($xmlrpcBoolean,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Change a template. Not implemented for MyPHPBlog."
			),
			"blogger.getPost" =>
			array("function" => "getPost",
				"signature" => array(array($xmlrpcStruct,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Get a particular blog posting"
			),
			"blogger.getRecentPosts" =>
			array("function" => "getRecentPosts",
				"signature" => array(array($xmlrpcArray,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcInt)),
				"doc" => "Get a list of recent blog posts"
			),
			"metaWeblog.newPost" =>
			array("function" => "mw_newPost",
				"signature" => array(array($xmlrpcBoolean,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcStruct,$xmlrpcBoolean)),
				"doc" => "Post a new item"
			),
			"metaWeblog.editPost" =>
			array("function" => "mw_editPost",
				"signature" => array(array($xmlrpcBoolean,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcStruct,$xmlrpcBoolean)),
				"doc" => "Edit an item"
			),
			"metaWeblog.getPost" =>
			array("function" => "mw_getPost",
				"signature" => array(array($xmlrpcStruct,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Get a particular blog posting"
			),
			"metaWeblog.getRecentPosts" =>
			array("function" => "mw_getRecentPosts",
				"signature" => array(array($xmlrpcArray,$xmlrpcString,$xmlrpcString,$xmlrpcString,$xmlrpcInt)),
				"doc" => "Get a list of recent blog posts"
			),
			"metaWeblog.getCategories" =>
			array("function" => "mw_getCategories",
				"signature" => array(array($xmlrpcArray,$xmlrpcString,$xmlrpcString,$xmlrpcString)),
				"doc" => "Get a list of categories"
			),
			"pingback.ping" =>
            array("function" => "pingback_ping",
                "signature" => array(array($xmlrpcString,$xmlrpcString,$xmlrpcString)),
                "doc" => "Process pingback requests"
														            ),
	)
);

?>

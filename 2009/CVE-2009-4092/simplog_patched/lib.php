<?PHP
##
##
## lib.php
##
## file for global variables and functions
##
## CHANGES - please view the CVS log

$res = array();

#if you are using php 4.0.6 and earlier, uncomment this next line
# pre41vars();

require('config.php');
include_once("class.BlogInfo.php");
include_once("class.BlogEntry.php");

#open connection to DB
require_once("adodb/adodb-errorhandler.inc.php");
require_once("adodb/adodb.inc.php");
$db = NewADOConnection($dbtype);
$db->PConnect($host,$user,$passwd, $dbase);
$ADODB_FETCH_MODE = ADODB_FETCH_ASSOC;

//define field types for spam filters
define('TB_URL',1);
define('TB_BLOG_NAME',2);
define('TB_EXCERPT',3);
define('COMMENT_NAME',4);
define('COMMENT_BODY',5);

#
# use_new_vars - for <= php4.0.6 to set all PHP variables to use $_ style in php > 4.1.x
#

function pre41vars() {

	global $_REQUEST, $HTTP_GET_VARS, $_SESSION, $HTTP_COOKIE_VARS, $HTTP_ENV_VARS, $HTTP_SERVER_VARS, $HTTP_POST_FILES, $_REQUEST, $_SESSION, $_SERVER, $_ENV, $_COOKIE, $_POST, $_GET, $_FILES;

	$_COOKIE = $HTTP_COOKIE_VARS;
	$_SESSION = $HTTP_SESSION_VARS;
	$_ENV = $HTTP_ENV_VARS;
	$_SERVER = $HTTP_SERVER_VARS;
	$_GET = $HTTP_GET_VARS;
	$_POST = $HTTP_POST_VARS;
	$_FILES = $HTTP_POST_FILES;
	

	if($HTTP_SERVER_VARS['REQUEST_METHOD'] == "GET") {
		$_REQUEST = $HTTP_GET_VARS;
	} else {
		$_REQUEST = $HTTP_POST_VARS;
	}

}



#
# escape - escapes input if magic quotes not turned on
#
function escape($var) {

	if(!get_magic_quotes_gpc()) {
	        $var = addslashes($var);
	}

	return $var;

}

#
# auth - authenticates the user based on the session
#
function auth() {
	
	if(!isset($_SESSION['login'])) { #if login is ! in the session
		header("Location: login.php?act=login\n\n");
		exit(0);
	} elseif(!isset($_SESSION['ip'])) { # if the ip is ! in the session
		header("Location: login.php?act=ip\n\n");
		exit(0);
	} elseif($_SESSION['ip'] != $_SERVER['REMOTE_ADDR']) { # if the ip in session is != to the ip of the client
		//echo $_SESSION['ip'] ."!=". $_SERVER['REMOTE_ADDR'];
		header("Location: login.php?hijack\n\n");
		exit(0);
		#error_log($_SERVER['REMOTE_ADDR']." - attempted session hijack\n",3,"security.log"); #log attempt
	}
} 

#
# isLoggedIn - sees if user is logged in based on the session
#
function isLoggedIn() {

    if(isset($_SESSION['login']) and ($_SESSION['ip'] == $_SERVER['REMOTE_ADDR'])) { 
		return 1;	
    } else {
		return 0;
    }

}

#
# adminemail - returns email address of admin user
#

function adminemail() {

	global $db;

	$sql = "SELECT email from blog_users where admin=1";
	$res = $db->Execute($sql);

	return $res->fields['email'];

}

#
# isAdmin - checks is user is admin user
#

function isAdmin() {

	global $db;

	if(isset($_SESSION['login'])) {
	
		$sql = "select admin from blog_users where login='".$_SESSION['login']."'";
		$res = $db->Execute($sql);

		return $res->fields['admin'];
	} else {
		return false;
	}
}

#
# userHasRights - if user is in blog acl
#

function userHasRights($uid,$users) {

	global $blogid;

	if(isBlogAdmin($blogid) or isAdmin()) {
		return 1;
	} else {

		foreach($users as $user) {
			if($user->userId == $uid) {
				return 1;
			}
		}

	}

	return 0;

}

#
# get_reqs - returns number of blog requests
#

function get_reqs() {

	global $db;

	$sql = "select count(*) as count from blog_request";
	$res = $db->Execute($sql);

	return $res->fields['count'];

}

#
# print_login - outputs login form
#
function print_login() {

	global $baseurl,$blogid;
	echo make_login();	
}	

function make_login(){
	global $baseurl,$blogid;

    $string = "<div align=center>
		  <form action=\"$baseurl/login.php?blogid=$blogid\" method=post>
		    <table cellpadding=4 cellspacing=0 border=0 style=\"padding:4px;border:1px solid #999999;\">
            <tr>
            <td>
                Login:
            </td>
            <td>
                <input type=text name=ulogin size=15 max=20>
            </td>
            </tr>
            <tr>
            <td>
                Password:
            </td>
            <td>
                <input type=password name=password size=8>
            </td>
            </tr>
            </table>
		  <input type=hidden name=act value=\"login\">
          <input class=search type=submit value=\"Sign In\">
          </form>
		  <p></p>
		  <a class=small href=\"login.php?act=change\">Forget your password?</a><p>
		  </div>
    \n";
return $string;
}
 
#
# print_form - outputs blog entry form
#
function print_form($etitle = "",$bod = "") {

	global $uid, $blogid, $use_weblog_rpc, $enable_trackback, $enable_pingback, $enable_smilies, $enable_flickr;

	if($blogid) {

		echo "
		  <p>
		  <form action=\"preview.php\" method=POST target=\"preview\" name=prev>
		  <input type=hidden name=etitle>
		  <input type=hidden name=body>
		  <input type=hidden name=blogid value=\"$blogid\">
          <input type=hidden name=uid value=\"$uid\">
		  <input type=hidden name=cid>
		  <input type=hidden name=trans>
		  <input type=hidden name=format>
		  </form>
		  <form action=\"edit.php\" method=POST name=entry>
          <p>
		  <table width=100%>
			<tr><td colspan=3 bgcolor=\"#dddddd\" style=\"border:1px solid #999999;\"><b>New Entry</b></td></tr>
			<tr><td align=right bgcolor=\"#eeeeee\">Category: </td><td>".category_list()."</td></tr>
			<tr><td align=right bgcolor=\"#eeeeee\">Title:</td>
			<td><input type=text size=40 maxlength=128 name=etitle value=\"$etitle\">";
			
	if($enable_flickr) {
		if(hasFlickrAccount($_SESSION['login'])) {
			echo " [<a href=\"javascript: openImg();\">Add an image</a>]";
		}
	}
			
			print "</td></tr>
			
			<tr>
			<td align=right valign=top bgcolor=\"#eeeeee\">Entry:</td>
			<td>
			<textarea name=\"body\" rows=10 cols=50 wrap=auto>$bod</textarea></td><td>";
		//include ("add_symbols.inc");

        echo "</td></tr>";
			echo "<tr><td align=right bgcolor=\"#eeeeee\">Manual trackback URLs</td><td><textarea name=\"man_tb\" rows=3 cols=50 wrap=auto></textarea></td></tr>";
		
		echo "</table>";
		//	include ("add_html.inc");
		 echo"<p>
		  <input class=search type=submit value=\"Save\">&nbsp;
		  <input type=button class=search value=\"Preview\" onclick=\"javascript: openPrev();\">
          
    	\n";
		
		if($enable_smilies) {
			echo "Add Smiley:
			<a href=\"javascript: add_smiley(':)');\"><img src=\"images/smile/icon_smile.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':^d');\"><img src=\"images/smile/icon_biggrin.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':(');\"><img src=\"images/smile/icon_sad.gif\" border=0></a>
			<a href=\"javascript: add_smiley(';)');\"><img src=\"images/smile/icon_wink.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':^p');\"><img src=\"images/smile/icon_razz.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':|');\"><img src=\"images/smile/icon_neutral.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':x');\"><img src=\"images/smile/icon_mad.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':o');\"><img src=\"images/smile/icon_surprised.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':?');\"><img src=\"images/smile/icon_confused.gif\" border=0></a>
			<a href=\"javascript: add_smiley(':\'(');\"><img src=\"images/smile/icon_cry.gif\" border=0></a>
			<a href=\"javascript: add_smiley('>:)');\"><img src=\"images/smile/icon_evil.gif\" border=0></a><br>\n";
		}

		echo "		  <input type=hidden name=blogid value=\"$blogid\">
		  <input type=hidden name=act value=\"save\">
		  <input type=checkbox name=format value=\"1\" CHECKED>preserve formatting<br>
		  <input type=checkbox name=trans value=\"1\" CHECKED>translate links(http, mailto)<br>";

		  if($use_weblog_rpc) {
		  	echo "<input type=checkbox name=ping value=\"1\">send update notice to weblogs.com<br>(may cause longer load time)<br>";
		  }

		  if($enable_trackback) {
                  echo "<input type=checkbox name=tb value=\"1\">send trackback ping<br>";
          }

		  if($enable_pingback) {
	              echo "<input type=checkbox name=pb value=\"1\">send pingback<br>";
          }

		echo "</form><p>";
		 

	} else {
		echo "<center><b>You have no blogs.  Please click 'Request' in the menu above to request a new blog.</b></center><p>\n";
	}

} 

#
# print_edit - outputs blog editing form
#
function print_edit($etitle,$bod,$pid,$cid) {
 
    global  $uid, $blogid, $enable_trackback, $enable_pingback, $use_weblog_rpc, $enable_smilies, $enable_flickr;

    echo "
          <p>
		  <form action=\"preview.php\" method=POST target=\"preview\" name=prev>
          <input type=hidden name=etitle>
          <input type=hidden name=body>
          <input type=hidden name=blogid value=\"$blogid\">
          <input type=hidden name=uid value=\"$uid\">
	  <input type=hidden name=cid>
          <input type=hidden name=trans>
          <input type=hidden name=format>
		  </form>
          <form action=\"edit.php\" method=POST name=entry>
          <p>
		  <table width=100%>
              <tr>
              <td colspan=2 bgColor=\"#dddddd\" style=\"border:1px solid #999999;\">
            <b>Edit Entry</b>
            </td>
            </tr>
            <tr>
            <td align=right bgcolor=\"#eeeeee\">
          Category:
            </td>
            <td>".category_list($cid)."</td>
           </tr>
           <tr>
            <td align=right bgcolor=\"#eeeeee\">Title:</td>
            <td><input type=text size=40 maxlength=128 name=etitle value=\"$etitle\">";
	    
	    if($enable_flickr) {
                    if(hasFlickrAccount($_SESSION['login'])) {
                            echo " [<a href=\"javascript: openImg();\">Add an image</a>]";
                    }
            }
	    
	    print "</td>
          </tr>
           <tr>
           <td align=right valign=top bgcolor=\"#eeeeee\">Entry:</td>
           <td>
          <textarea name=\"body\" rows=10 cols=50 wrap=auto>$bod</textarea></td><td>";
		//include ("add_symbols.inc");
          echo " </td></tr>";
			echo "<tr><td align=right bgcolor=\"#eeeeee\">Manual trackback URLs</td><td><textarea name=\"man_tb\" rows=3 cols=50 wrap=auto></textarea></td></tr>";
		

         echo "</table>";

		//include ("add_html.inc");
		echo "<p>
          <input class=search type=submit value=\"Update\">&nbsp;
		  <input type=button class=search value=\"Preview\" onclick=\"javascript: openPrev();\">&nbsp;
		  <input class=search type=button value=\"Cancel\" onclick=\"document.location='edit.php?blogid=$blogid';\">
      	  ";
	if($enable_smilies) {

		echo "Add Smiley:
                        <a href=\"javascript: add_smiley(':)');\"><img src=\"images/smile/icon_smile.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':D');\"><img src=\"images/smile/icon_biggrin.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':(');\"><img src=\"images/smile/icon_sad.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(';)');\"><img src=\"images/smile/icon_wink.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':P');\"><img src=\"images/smile/icon_razz.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':|');\"><img src=\"images/smile/icon_neutral.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':x');\"><img src=\"images/smile/icon_mad.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':o');\"><img src=\"images/smile/icon_surprised.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':?');\"><img src=\"images/smile/icon_confused.gif\" border=0></a>
                        <a href=\"javascript: add_smiley(':\'(');\"><img src=\"images/smile/icon_cry.gif\" border=0></a>
                        <a href=\"javascript: add_smiley('>:)');\"><img src=\"images/smile/icon_evil.gif\" border=0></a><br>\n";
	}

  	echo "        <input type=hidden name=act value=\"update\">
		  <input type=hidden name=blogid value=\"$blogid\">
		  <input type=hidden name=pid value=\"$pid\">
		  <input type=checkbox name=format value=\"1\" CHECKED>preserve formatting<br>
          <input type=checkbox name=trans value=\"1\" CHECKED>translate links(http, mailto)<br>";
		  
	 		if($use_weblog_rpc) {
            echo "<input type=checkbox name=ping value=\"1\">send update notice to weblogs.com<br>(may cause longer load time)<br>";
          }

          if($enable_trackback) {
                  echo "<input type=checkbox name=tb value=\"1\">send trackback ping<br>";
          }

          if($enable_pingback) {
                  echo "<input type=checkbox name=pb value=\"1\">send pingback<br>";
          }	
		echo "</form><p>";

} 

#
# category_list - buils and outputs dropdown of all categories
#

function category_list($cid=1) {

	global $db, $blogid;

	$sql = "SELECT * from blog_categories where blog_id=$blogid";
	$res = $db->Execute($sql);

	$ret = "<select name=\"cid\">\n";
	while (!$res->EOF) {

		$ret .= "<option value=\"".$res->fields['cat_id']."\"";
		
		if($res->fields['cat_id'] == $cid) {
			$ret .= " SELECTED";
		}
		
		$ret .= ">".$res->fields['cat_name']."\n";
		$res->MoveNext();
	}
    $ret .= "</select>\n";

	if(isBlogAdmin($blogid)) {
		$ret .= "<span class=small>[<a href=catadmin.php?blogid=$blogid>New Category</a>]</span>";
	}

	return $ret;
}

#
# blog_list - builds and outputs dropdown of all blogs for blog administration
#
function blog_list($bid=0) {

	global $db, $conn;

	$sql = "SELECT blog_id,title from blog_list order by blog_id";
	$res = $db->Execute($sql);
	while (!$res->EOF) {
		echo "<option value=\"".$res->fields['blog_id']."\"";
		if($res->fields['blog_id'] == $bid) {
			echo " SELECTED";
		}
		echo ">".$res->fields['title']."\n";
		$res->MoveNext();
	}

}

#
# tem_select - builds dropdown of available templates
#
function tem_select() {

	global $db, $blogid, $btemp;

	echo "<table><tr><td bgColor=\"#dddddd\" style=\"border:1px solid #999999;\"><b>Current Template</b></td><td>\n";

	if(isBlogAdmin($blogid) or isAdmin()) {
	
		echo "<form action=\"edit.php\" method=POST>\n";
		echo "<select name=templ onChange=\"submit();\">\n";
		$sql = "SELECT temp_id,name from blog_template order by name";
		$res = $db->Execute($sql);
		while (!$res->EOF) {
			echo "<option value=\"".$res->fields['temp_id']."\"";
			if($res->fields['temp_id'] == $btemp) {
				echo " SELECTED";
			}
			echo ">".$res->fields['name']."\n";
			$res->MoveNext();
		}
		echo "</select>\n<input type=hidden name=act value=\"templ\">\n";
		echo "<input type=hidden name=blogid value=\"$blogid\">\n";
		echo "<!--input type=submit class=search value=\"Change\"-->\n</form>\n";
	} else {
		$sql = "SELECT name from blog_template where temp_id=$btemp";
		$res = $db->Execute($sql);
		echo " ".$res->fields['name']."\n";
	}

	echo "</td></tr></table>\n";

}

#
# isBlogAdmin - determines whether a user is an admin for a blog
#
function isBlogAdmin($blogid) {

	global $uid, $db;

	if(isset($uid)) {
	
		$sql = "SELECT admin from blog_list where blog_id=$blogid";
		$res = $db->Execute($sql);

		$sql = "SELECT admin from blog_acl where blog_id=$blogid AND user_id=$uid";
		$res2 = $db->Execute($sql);

		// Return true if the user is an admin for this blog
		// or is the superadmin
		if($res->fields['admin'] == $uid || $res2->fields['admin'] == 'Y' || isAdmin()) {
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

#
# blog_select - builds dropdown of user's blogs
#
function blog_select($uid) {

	global $btitle, $db, $conn;

	echo "<form action=\"index.php\" method=POST>\n";
	echo "Current Blog:";
	echo "<select  class=small name=blogid onChange=\"submit();\">\n";
	$sql = "SELECT blog_id from blog_acl where user_id=$uid order by blog_id";
	$res = $db->Execute($sql);
	while (!$res->EOF) {
     		$sql2 = "SELECT title from blog_list where blog_id=".$res->fields['blog_id'];
			$res2 = $db->Execute($sql2);
	     	echo "<option value=\"".$res->fields['blog_id']."\"";
	     	if($res2->fields['title'] == $btitle) {
          		echo " SELECTED";
     		}
       		echo ">".$res2->fields['title']." - ".$res->fields['blog_id']."\n";
	$res->MoveNext();
	}

	echo "</select>\n<!--input class=search type=submit value=\"Change\"-->\n</form>\n";
}

#
# req_form - outputs new blog request form
#
function req_form() {

	global $blogid;

	echo "<P><b>Request New Blog</b>:<br>\n";
	echo "<form action=\"edit.php\" method=POST>\n";
	echo "Blog Title: <input type=text size=16 maxlength=32 name=blogtitle><br>";
	echo "Reason/Users to give acces to:<br>\n";
	echo "<textarea name=reason cols=40 rows=5 wrap=physical></textarea><br>\n";
	echo "<input type=hidden name=blogid value=\"$blogid\">\n";
	echo "<input class=search type=submit value=\"Send Request\">\n";
	echo "</form><P>\n";
	
}

#
# show_menu - outputs user/admin function menu
#
function show_menu() {

	global $blogid, $admin, $blogurl, $baseurl, $uid;

	echo '
        <table width=100% cellpadding=2 cellspacing=0 border=0 class="menu">
            <tr valign="middle">
                <td class="small" align=left>
				<A href="'.$baseurl.'/edit.php?blogid='.$blogid.'">Add/Edit Entries</A> | 
				<A href="'.$baseurl.'/user.php?blogid='.$blogid.'">User Info</A> | 
				<a href="'.$baseurl.'/news.php?blogid='.$blogid.'">News Feeds</a> | 
				<A href="'.$blogurl.'?blogid='.$blogid.'">View Blog</A> | ';

	echo "<a href=\"mailto: ".adminemail()."\">Contact Admin</a> | ";
	echo "<A href=\"javascript: openHelp('http://www.simplog.org/wiki/');\">Help</A> | 
			  <A href=\"".$baseurl."/logout.php?blogid=$blogid\">Logout</A>
				</td>";
	echo "<td align='right' valign='middle' class='small'>";
	blog_select($uid);
        echo '</td>			</tr>
        </TABLE>
      ';
	
	if(isBlogAdmin($blogid)) {
		admin_menu();
	}

}

#
# admin_menu - outputs user/admin function menu
#
function admin_menu() {

    global $blogid, $blogurl, $baseurl;

    echo '
        <table cellpadding=2 cellspacing=0 border=0 class="header" width=100%>
            <tr>
                <td class="small">Blog Level Administration: 
                <A href="'.$baseurl.'/blogadmin.php?blogid='.$blogid.'">Add/Edit Users</A> |
                <A href="'.$baseurl.'/blocksadmin.php?blogid='.$blogid.'">Blocks</A> |
				<a href="'.$baseurl.'/catadmin.php?blogid='.$blogid.'">Categories</a>
                </td>';

	if(isAdmin()) {
		echo '<td align=right class="small">System: <a href="'.$baseurl.'/admin.php?adm=spam&blogid='.$blogid.'">IP/Spam Control</a> | <a href="'.$baseurl.'/admin.php?adm=user&blogid='.$blogid.'">User Administration</a> | <a href="'.$baseurl.'/admin.php?adm=blog&blogid='.$blogid.'">Blog Administration</a> | <a href="'.$baseurl.'/admin.php?adm=tem&blogid='.$blogid.'">Template Administration</a></td>';
	}

            echo "</tr></TABLE>";

}

#
# format_date - UNIX timestamp to a readable format.
#
function format_date($datetime) {
	$date = strftime("%m/%d/%y %I:%M %p", strtotime($datetime));
	return $date;
}

#
# short_date - converts unix timestamp to just a date
#
function short_date($datetime) {
 
     $date = strftime("%m/%d/%y", strtotime($datetime));
																 
     return $date;
}

#
# short_date - converts unix timestamp to just a date
#
function short_time($datetime) {
	 
     $time = strftime("%I:%M %p", strtotime($datetime));

     return $time;
}

#
# str_to_link - translates text links to web links
#

function str_to_link($str) {

	$str = stripslashes($str);

	$str = preg_replace("/\n/"," --space-- ",$str);
    $data = preg_split("/\s/",$str);
    $new = array();
		 
    for($i=0; $i<=sizeof($data); $i++) {
        $tmp = $data[$i];
        if(!preg_match("/href|>|\"|\'/",$tmp)) {
             $tmp = preg_replace("/((http(s?):\/\/)|(www\.))([\w\.]+)(\S*)/i","<a href=\"http$3://$4$5$6\" target=\"_blank\">$2$4$5$6</a>", $tmp);
             $tmp = preg_replace("/([\w\.]+)(@)([\w\.]+)/i","<a href=\"mailto:$0\">$0</a>",$tmp);
        }
        array_push($new,$tmp);
															  
    }
													   
    $str = implode(" ",$new);
    $str = ereg_replace(" --space-- ","\n",$str);
	$str = addslashes($str);

	return $str;
}

#
# marker_sub - does substitution for markers, links, emails in templates
#
function marker_sub($line,&$blogEntry,&$blogInfo) {

	global $act, $keyw, $trans, $format, $comment_win, $enable_smilies,$baseurl;


	if(preg_match("/preview\.php/",$_SERVER['SCRIPT_NAME'])) {
		if($_REQUEST['trans']) {
    			$blogEntry->entryBody = stripslashes(str_to_link($blogEntry->entryBody));
		}
	}

	#remove trailing spaces from each line
	$blogEntry->entryBody = preg_replace("/\040+\n/","\${1}\n\$3",$blogEntry->entryBody);

	if($blogEntry->entryFormat) {
		#add breaks
		$blogEntry->entryBody = nl2br($blogEntry->entryBody);
	}

		$blogEntry->entryBody = str_replace('><br />','>',$blogEntry->entryBody);
		$blogEntry->entryBody = str_replace('> <br />','>',$blogEntry->entryBody);

	if($enable_smilies) {
		$blogEntry->entryBody = do_smilies($blogEntry->entryBody);
	}

	$line = ereg_replace("--entryId--",$blogEntry->entryId,$line);
	$line = ereg_replace("--title--",$blogEntry->entryTitle,$line);
	$line = ereg_replace("--created--",$blogEntry->formattedPostDate,$line);
	$line = ereg_replace("--date--",$blogEntry->formattedEntryDate,$line);
	$line = ereg_replace("--shortdate--",short_date($blogEntry->entryDate),$line);
	$line = ereg_replace("--time--",short_time($blogEntry->entryDate),$line);
	$line = ereg_replace("--name--",$blogEntry->entryAuthorName,$line);
	$line = ereg_replace("--url--",$blogEntry->entryURL,$line);
	$line = ereg_replace("--email--",$blogEntry->entryAuthorEmail,$line);
	$line = ereg_replace("--body--","--body--<!--endpost-->",$line);
	$line = ereg_replace("--body--",stripslashes($blogEntry->entryBody),$line);
    	$templateId = $blogInfo->blogTemplateId;
	$line = ereg_replace("--comments--",$blogEntry->getCmntLink($comment_win, $templateId),$line);
	$line = ereg_replace("--karma--",$blogEntry->getFormattedKarmaLink(),$line);
	$line = ereg_replace("--link--",$blogEntry->getFormattedEntryLink(),$line);
	$line = ereg_replace("--category--",$blogEntry->getFormattedCategoryLink(),$line);
	$line = ereg_replace("--plink--",get_simple_link(@$row->fields['date']),$line);
    $line = ereg_replace("--guid--",@$blogurl .md5(@$row->fields['date']),$line);
	$line = ereg_replace("--postid--",get_postid(),$line);
	$line = ereg_replace("--edit--","<a href='".@$baseurl ."/edit.php?act=edit&blogid=".$blogInfo->blogId ."&pid=".$blogEntry->entryId."'>Edit</a>",$line);
	$line = ereg_replace("--trackbackurl--",@$baseurl ."/tb.php/$blogEntry->entryId",$line);
    $line = ereg_replace("--trackbacks--",tblink($blogEntry->entryId,@$row->fields['date']),$line);
	$line = ereg_replace("--tbrdf--",tb_rdf(),$line);
    $line = ereg_replace("--pingbacks--",pblink($blogEntry->entryId,@$row->fields['date']),$line);
    $line = ereg_replace("--rsscontent--",rss_content(@$row->fields['full_body']),$line);
	$line = do_tags($line);
    	return $line;
}


#
# do_smilies - substitute smiley for image
#
function do_smilies($body) {

	$body = ereg_replace(">:\(","<img src=\"images/smile/icon_evil.gif\">",$body);
        $body = ereg_replace(">:\)","<img src=\"images/smile/icon_evil.gif\">",$body);
	$body = ereg_replace(":^D","<img src=\"images/smile/icon_biggrin.gif\">",$body);
	$body = ereg_replace(":-D","<img src=\"images/smile/icon_biggrin.gif\">",$body);
	$body = ereg_replace(":\)","<img src=\"images/smile/icon_smile.gif\">",$body);
	$body = ereg_replace(":-\)","<img src=\"images/smile/icon_smile.gif\">",$body);
	$body = ereg_replace(":\(","<img src=\"images/smile/icon_sad.gif\">",$body);
        $body = ereg_replace(":-\(","<img src=\"images/smile/icon_sad.gif\">",$body);
	$body = ereg_replace(":o","<img src=\"images/smile/icon_surprised.gif\">",$body);
        $body = ereg_replace(":-o","<img src=\"images/smile/icon_surprised.gif\">",$body);
        $body = ereg_replace(":\?","<img src=\"images/smile/icon_confused.gif\">",$body);
        $body = ereg_replace(":-\?","<img src=\"images/smile/icon_confused.gif\">",$body);
	#$body = ereg_replace("8\)","<img src=\"images/smile/icon_cool.gif\">",$body);
        $body = ereg_replace("8-\)","<img src=\"images/smile/icon_cool.gif\">",$body);
        $body = ereg_replace(":x","<img src=\"images/smile/icon_mad.gif\">",$body);
        $body = ereg_replace(":-x","<img src=\"images/smile/icon_mad.gif\">",$body);
	$body = ereg_replace(":^P","<img src=\"images/smile/icon_razz.gif\">",$body);
        $body = ereg_replace(":-P","<img src=\"images/smile/icon_razz.gif\">",$body);
        $body = ereg_replace(";\)","<img src=\"images/smile/icon_wink.gif\">",$body);
        $body = ereg_replace(";-\)","<img src=\"images/smile/icon_wink.gif\">",$body);
	$body = ereg_replace(":\|","<img src=\"images/smile/icon_neutral.gif\">",$body);
        $body = ereg_replace(":-\|","<img src=\"images/smile/icon_neutral.gif\">",$body);
        $body = ereg_replace(":'\(","<img src=\"images/smile/icon_cry.gif\">",$body);

	//include "do_glyph.php";

	return $body;

}#
# do_smilies - substitute smiley for image
#

function do_tags($body) {

#	code below added by j. hu to deal with inserting html.

	$body = ereg_replace("<red>","<span style = 'color:red'>",$body);
	$body = ereg_replace("</red>","</span>",$body);
	$body = ereg_replace("<blue>","<span style = 'color:blue'>",$body);
	$body = ereg_replace("</blue>","</span>",$body);
	$body = ereg_replace("<green>","<span style = 'color:green'>",$body);
	$body = ereg_replace("</green>","</span>",$body);
	
	#hyperlinks - simplog already does these
	$body = ereg_replace("<url1>","<a href = '",$body);
	$body = ereg_replace("<url2>","'>",$body);
	$body = ereg_replace("</url>","</a>",$body);
	#images
	$body = ereg_replace("<image1>","<img src = '",$body);
	$body = ereg_replace("<image2>","' alt = '",$body);
	$body = ereg_replace("</image>","'>",$body);



	return $body;

}

#
# get_simple_link - Just the link, with no extra html.
#
function get_simple_link() {

	global $blogEntry;

    $str = htmlspecialchars($blogEntry->entryURL);

    return $str;

}

function get_postid() {
    global $pid;
    return 'pid' . $pid;
}


function rss_content($str) {
    $content = "<![CDATA[$str]]>\n";

    return $content;
}


#
# create_table - generates SQL for creating blog table
#
function create_table($tab) {

	global $dbtype;

	if($dbtype == "mysql") {
		$sql = "CREATE TABLE blog_$tab (
		   id int(11) NOT NULL,
		   body text NOT NULL,
		   date datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
		   userid int(11) NOT NULL,
		   title varchar(64),
		   karma int(11) DEFAULT '0' NOT NULL,
		   format int(4) DEFAULT '0' NOT NULL,
		   cat_id int(11) DEFAULT '0' NOT NULL,
		   PRIMARY KEY (id),
		   UNIQUE id (id))";
	} elseif($dbtype == "postgres") {
		$sql = "CREATE TABLE blog_$tab (
		   id INT4 NOT NULL,
		   body TEXT DEFAULT '' NOT NULL,
		   DATE TIMESTAMP DEFAULT '0001-01-01 00:00:00' NOT NULL,
		   userid INT4 NOT NULL,
		   title varchar(64),
		   karma INT4 DEFAULT '0' NOT NULL,
		   format INT4 DEFAULT '0' NOT NULL,
		   cat_id INT4 DEFAULT '0' NOT NULL,
		   PRIMARY KEY (id))";
	}

	return $sql;

}

#
# mk_drawCalendar - builds calander for archive script
#
function mk_drawCalendar($m,$y,$search=1)
{
	echo mk_Calendar($m,$y,$search=1);
}

function mk_Calendar($m,$y,$search=1)
{
    global $blogid, $db;
	 
    if ((!$m) || (!$y))
    {
         $m = date("n",mktime());
         $y = date("Y",mktime());
    }
								  
   /*== get what weekday the first is on ==*/
   $tmpd = getdate(mktime(0,0,0,$m,1,$y));
   $month = $tmpd["month"];
   $firstwday= $tmpd["wday"];
   $today = date("Ymd",mktime());
								   
   $lastday = mk_getLastDayofMonth($m,$y);


$string = '
<table><tr>
<td style="padding-left:12px;padding-right:12px;padding-top:4px;padding-bottom:4px;border:1px solid #999999;background-color:#eeeeee;">
		<table cellspacing="0" cellpadding="2" border="0">
					<tr>
						<td colspan="7" align="center"><b>'."$month $y".'</b>
						</td>
					</tr>
					<tr>

						<td width="19" align="center" class="calday">Sun</td>
						<td width="19" align="center" class="calday">Mon</td>
						<td width="19" align="center" class="calday">Tue</td>
						<td width="19" align="center" class="calday">Wed</td>
						<td width="19" align="center" class="calday">Thu</td>
						<td width="19" align="center" class="calday">Fri</td>
						<td width="19" align="center" class="calday">Sat</td>
					</tr>';
	$d = 1;
    $wday = $firstwday;
    $firstweek = true;

	 /*== loop through all the days of the month ==*/
	 while ( $d <= $lastday)
	 {
				 
	    /*== set up blank days for first week ==*/
	    if ($firstweek) {
	    	$string .= "<tr>";
	    	for ($i=1; $i<=$firstwday; $i++)
	    	{ $string .= "<td>&nbsp;</td>"; }
	    	$firstweek = false;
	    }
																						  
       /*== Sunday start week with <tr> ==*/
       if ($wday==0) { $string .= "<tr>"; }
															   
															    
       $mo = $m;
       if($mo <10) {
           if(!preg_match("/0\d/",$mo)) {
                $mo = "0".$mo;
           }
       }
																																								 
       $da = $d;
       if($da <10) {
            if(!preg_match("/0\d/",$da)) {
                 $da = "0".$da;
            }
       }
																																																						  
 		/*== Look for blog entries for this day ==*/
	   $sql = "select count(*) as count from blog_entries where blog_id = $blogid AND date like '$y-$mo-$da%'";
	   $res = $db->Execute($sql);

	  /*== check for event ==*/
      $showdate = $y.$mo.$da;

	  $string .= "<td align=center class=calday";
      if($showdate == $today) {
	       $string .= " bgcolor=gainsboro";
	  } 
	  $string .= ">";

	  /*== if entries are found, output link to that days entries ==*/
	  if($res->fields['count'] > 0) {
	       $string .= "<a href=\"archive.php?m=$mo&d=$da&y=$y&blogid=$blogid\">$d</a>";
	  } else {
	       $string .= $d;
	  }
	  $string .= "</td>\n";

	  /*== Saturday end week with </tr> ==*/
      if ($wday==6) { $string .= "</tr>\n"; }
	   
      $wday++;
      $wday = $wday % 7;
      $d++;
	}

	if($wday != 0) {
		for($i=$wday; $i <7; $i++) {
			$string .= "<td></td>\n";
		}
		$string .= "</tr>\n";
	}

	#determine next and previous month
	if(($m-1)<1) { $pm = 12; } else { $pm = $m-1; }
	if(($m+1)>12) { $nm = 1; } else { $nm = $m+1; }

	if(strlen($pm) == 1) { $pm = "0".$pm; };
	if(strlen($nm) == 1) { $nm = "0".$nm; };

$string .= '<tr><td colspan=3 align=right>';

$py = (($m-1)<1) ? $y-1 : $y;

$string .= "<b><a href=\"archive.php?m=$pm&y=$py&blogid=$blogid\">".getPrevMo($mo)."</a></b>
</td><td><br></td>";

$ny = (($m+1)>12) ? $y+1 : $y;

$string .= "<td colspan=3 align=left><b><a href=\"archive.php?m=$nm&y=$ny&blogid=$blogid\">".getNextMo($mo)."</b></a></td></tr>
</table>";
if($search){
$string .= "<div align=center>
<hr>
<form action=\"archive.php\" method=POST>
<input type=hidden name=blogid value=\"$blogid\">
<input type=hidden name=act value=\"search\">
<input type=text class=search2 name=keyw><br><input class=search type=submit value=\"Search\">
</form>
</div>";
}
$string .="</td></tr></table><br>";

return $string;
/*== end drawCalendar function ==*/
}
   
function getPrevMo($mo) {

	$mo--;

	if($mo == 0) {
		$mo = 12;
	}

	switch($mo) {
		case 1:
			return "Jan";
			break;
		case 2:
			return "Feb";
			break;
		case 3: 
			return "Mar";
			break;
		case 4:
			return "Apr";
			break;
		case 5:
			return "May";
			break;
		case 6:
			return "Jun";
			break;
		case 7:
			return "Jul";
			break;
		case 8:
			return "Aug";
			break;
		case 9:
			return "Sep";
			break;
		case 10:
			return "Oct";
			break;
		case 11:
			return "Nov";
			break;
		case 12:
			return "Dec";
			break;
		default:
			return "???";
			break;
	}
}
   

function getNextMo($mo) {

	$mo++;

    if($mo == 13) {
        $mo = 1;
    }

    switch($mo) {
        case 1:
            return "Jan";
            break;
        case 2:
            return "Feb";
            break;
        case 3:
            return "Mar";
            break;
        case 4:
            return "Apr";
            break;
        case 5:
            return "May";
            break;
        case 6:
            return "Jun";
            break;
        case 7:
            return "Jul";
            break;
        case 8:
            return "Aug";
            break;
        case 9:
            return "Sep";
            break;
        case 10:
            return "Oct";
            break;
        case 11:
            return "Nov";
            break;
        case 12:
            return "Dec";
            break;
        default:
			break;
	}
}

function getThisMo($mo) {

    switch($mo) {
        case 1:
            return "January";
            break;
        case 2:
            return "February";
            break;
        case 3:
            return "March";
            break;
        case 4:
            return "April";
            break;
        case 5:
            return "May";
            break;
        case 6:
            return "June";
            break;
        case 7:
            return "July";
            break;
        case 8:
            return "August";
            break;
        case 9:
            return "September";
            break;
        case 10:
            return "October";
            break;
        case 11:
            return "November";
            break;
        case 12:
            return "December";
            break;
        default:
            break;
    }
}

/*== get the last day of the month ==*/
function mk_getLastDayofMonth($mon,$year)
{
    for ($tday=28; $tday <= 31; $tday++)
    {
        $tdate = getdate(mktime(0,0,0,$mon,$tday,$year));
        if ($tdate["mon"] != $mon)
	        { break; }
							 
    }
    $tday--;
								  
    return $tday;
}

/*== Clean up user input ==*/
function safeHTML($html, $tags = "b|br|i|u|ul|ol|li|p|a|blockquote|em|strong") {
// removes all tags that are considered unsafe
// Adapted from a function posted in the comments about the strip_tags()
// function on the php.net web site.
//
// This function is not perfect! It can be bypassed!
// Remove any nulls from the input
	$html = preg_replace('/\0/', '', $html);
 
	// convert the ampersands to null characters (to save for later)
	$html = preg_replace('/&/', '\0', $html);
  
	// convert the sharp brackets to their html code and escape special characters such as "
	$html=htmlspecialchars($html);
   
    // restore the tags that are considered safe
    if ($tags) {
    	// Fix start tags
        $html = preg_replace("/&lt;(($tags).*?)&gt;/i", '<$1>', $html);
        // Fix end tags
        $html = preg_replace("/&lt;\/($tags)&gt;/i", '</$1>', $html);
        // Fix quotes
        $html = preg_replace("/&quot;/", '"', $html);
        $html = addslashes($html);
        // Don't allow, e.g. <a href="javascript:evil_code">
        $html = preg_replace("/<($tags)([^>]*)>/ie", "'<$1' . stripslashes(str_replace('javascript','hackerscript','$2')) .'>'", $html);
        // Don't allow, e.g. <img src="foo.gif" onmouseover="evil_javascript">
        $html = preg_replace("/<($tags)([^>]*)>/ie", "'<$1' . stripslashes(str_replace(' on',' off','$2')) .'>'", $html);
        $html = stripslashes($html);
																		    
	}
																									 
	// restore the ampersands
	$html = preg_replace('/\0/', '&', $html);
		  
	return($html);
} // safeHTML


#
# getLastInsertID
#
# retrieves the pid for the last entry into a blog
#

function getLastInsertID($blogid) {

	global $db;

	$sql = "select max(blog_entry_id) as pid from blog_entries where blog_id=$blogid";
	$res = $db->Execute($sql);

	return $res->fields['pid'];

}

#
# unhtmlentities
#
# traslates HTML special characters back to ASCII
#
function unhtmlentities ($string)
{
    $trans_tbl = get_html_translation_table (HTML_ENTITIES);
    $trans_tbl = array_flip ($trans_tbl);
    return strtr ($string, $trans_tbl);
}

#
# get_feed
#
# determines whether or not to get a news feed remotely or from cache and reads it into a string
#

function get_feed($fid,$url) {

	global $timeout, $basepath;
	$write = 0;

	$secs = $timeout * 60; # number of seconds in timeout value

	$file = $basepath."/cache/".$fid.".xml";

	#if feed in cache
	if(file_exists($file)) {
		#check age of cache file
		$data = stat($file);
		$now = time();
		if(($now - $data[10]) > $secs) { #if timedout
			#read from source	
			$xmlstr = getContentFromUrl($url);
			$write = 1;
		} else {
			#read in from cache
			$xmlstr = implode(" ",file($file));
		}

	} else { #DNE, read from source
		$xmlstr = getContentFromUrl($url);
		
		$write = 1;
	}

	if($write) { #write file to cache
        // jlb: adding file:/ to the start of the file name fixed
        // some caching problems that I was experiencing.
        #$file="file:/" + $file;
		$fp = fopen($file,"w");
		fputs($fp,$xmlstr);
	}

		include_once("$basepath/class.RSS.php");
		$rss = new MagpieRSS($xmlstr);
		if($rss->feed_type == "Atom") {
			$rss->channel['description'] = $rss->channel['tagline'];
			for($i=0;$i<count($rss->items);$i++) {
                       		$rss->items[$i]['description'] = $rss->items[$i]['atom_content'];
                	}
		}
		#$rss->show_list();		

		return $rss;
}

#
# getContentFromUrl
#
# read content from a URL
#

function getContentFromUrl($url) {

	require_once("class.HttpClient.php");

	$urlobj = parse_url($url);

	$http_client = new HttpClient($urlobj['host']);

	// Post the data
    	$status = $http_client->get($urlobj['path'],$urlobj['query']);

    	if ($status == true) {
        	$rsp = $http_client->getContent();
    	} else {
        	$rsp = "Doh! Status: ".$http_client->getError();
    	}

	return $rsp;

}

#
# add_block
#
# add a new sideblock
#

function add_block() {

	global $db, $blogid;

	$res = $db->Execute("select max(blk_order)+1 as ord from blog_blocks where blog_id=$blogid");
	$ord = $res->fields['ord'];

	if(!is_numeric($ord)) {
		$ord=1;
	}

	if($_REQUEST['type'] == 1) {
		$res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Categories',$ord)");
		echo "<br><b>Block Added!</b><p>\n";
	} elseif($_REQUEST['type'] == 2) {
echo "<table width=100%>
<tr>
<td class=header><b>Add RSS Headline Block</b></td>
</tr>
<tr>
<td>
<form method=POST action=blocksadmin.php?blogid=$blogid&op=save>
Pick a News Feed: <select name=rss_id>";

$res = $db->Execute("SELECT * from blog_rss");
while(!$res->EOF) {

	echo "<option value=\"".$res->fields['rss_id']."\">".$res->fields['title']."</option>\n";
	$res->MoveNext();
}

echo "</select>
<input type=hidden name=ord value=\"$ord\">
<input type=hidden name=type value=\"".$_REQUEST['type']."\">
<input type=submit class=search value=\"Save\"></form></td>
</tr>
</table>\n";	

	} elseif($_REQUEST['type'] == 3) {
		$res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Previous Entries',$ord)");
        echo "<br><b>Block Added!</b><p>\n";	
	} elseif($_REQUEST['type'] == 4) {
		$res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Archives',$ord)");
        echo "<br><b>Block Added!</b><p>\n";
	} elseif(($_REQUEST['type'] == 5) or ($_REQUEST['type'] == 6)) {

		echo "<table width=100%>
	<tr>
	<td class=header><b>Add "; 

		if($_REQUEST['type'] == 5) { echo "PHP"; } else { echo "HTML"; }

		echo " Block</b></td>
	</tr>
	<tr>
	<td>
	<form method=POST action=blocksadmin.php?blogid=$blogid&op=save>
		<table>
		<tr><td bgcolor=#eeeeee align=right>Block Title:</td><td><input type=text name=blk_title></td></tr>
		<tr><td bgcolor=#eeeeee align=right valign=top>Block Content:</td><td><textarea name=content cols=40 rows=8></textarea></td></tr>
		</table>
		<input type=hidden name=ord value=\"$ord\">
 		<input type=hidden name=type value=\"".$_REQUEST['type']."\">
		<input type=submit class=search value=\"Save\">
	</form>
	</td>
	</tr>
	</table>
\n";

	} elseif($_REQUEST['type'] == 7) {
		$res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Search',$ord)");
        echo "<br><b>Block Added!</b><p>\n";
	} elseif($_REQUEST['type'] == 8) {
	        $res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Login',$ord)");
	        echo "<br><b>Block Added!</b><p>\n";
	} elseif($_REQUEST['type'] == 9) {
            $res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Calendar',$ord)");
            echo "<br><b>Block Added!</b><p>\n";
    } elseif($_REQUEST['type'] == 10) {
            $res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'XML Feeds',$ord)");
            echo "<br><b>Block Added!</b><p>\n";
	}  elseif($_REQUEST['type'] == 11) {
            $res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Recent Trackbacks',$ord)");
            echo "<br><b>Block Added!</b><p>\n";
	}  elseif($_REQUEST['type'] == 12) {
            $res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,blk_order) values (".$_REQUEST['type'].",$blogid,'Recent Comments',$ord)");
            echo "<br><b>Block Added!</b><p>\n";
	}
}


#
# save_block
#
# save side block
#

function save_block() {

	global $db, $blogid;

	if($_REQUEST['type'] == 2) {
		
		$res = $db->Execute("SELECT * from blog_rss where rss_id=".$_REQUEST['rss_id']);

		$res2 = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,rss_id,blk_order) values (".$_REQUEST['type'].",$blogid,'".$res->fields['title']."',".$_REQUEST['rss_id'].",".$_REQUEST['ord'].")");

		echo "<br><b>RSS Block Saved!</b><p>\n";

	} elseif(($_REQUEST['type'] == 5) or ($_REQUEST['type'] == 6)) {

		$res = $db->Execute("INSERT into blog_blocks (blk_type_id,blog_id,title,content,blk_order) values (".$_REQUEST['type'].",$blogid,'".$_REQUEST['blk_title']."','".$_REQUEST['content']."',".$_REQUEST['ord'].")");

		echo "<br><b>"; 
		if($_REQUEST['type'] == 5) { echo "PHP"; } else { echo "HTML"; }
		echo " Block Saved!</b><p>\n";

	}

}

#
# edit_block
#
# edit side block
#

function edit_block($blk_id) {

	global $db, $blogid;

	$res = $db->Execute("select * from blog_blocks where blk_id=$blk_id");

	if($res->fields['blk_type_id'] == 2) {
		echo "<table width=100%>
<tr>
<td class=header><b>Edit RSS Headline Block</b></td>
</tr>
<tr>
<td>
<form method=POST action=blocksadmin.php?blogid=$blogid&op=update>
Pick a News Feed: <select name=rss_id>";

		$res2 = $db->Execute("SELECT * from blog_rss");
		while(!$res2->EOF) {
    		echo "<option value=\"".$res2->fields['rss_id']."\"";

			if($res2->fields['rss_id'] == $res->fields['rss_id']) {
				echo " SELECTED";
			}

			echo ">".$res2->fields['title']."</option>\n";
		    $res2->MoveNext();
		}

		echo "</select>
<input type=hidden name=blk_id value=\"$blk_id\">
<input type=submit class=search value=\"Update\"></form></td>
</tr>
</table>\n";

    } elseif(($res->fields['blk_type_id'] == 5) or ($res->fields['blk_type_id'] == 6)) {

        echo "<table width=100%>
    <tr>
    <td class=header><b>Edit ";

        if($res->fields['blk_type_id'] == 5) { echo "PHP"; } else { echo "HTML"; }

        echo " Block</b></td>
    </tr>
    <tr>
    <td>
    <form method=POST action=blocksadmin.php?blogid=$blogid&op=update>
        <table>
        <tr><td bgcolor=#eeeeee align=right>Block Title:</td><td><input type=text name=blk_title value=\"".$res->fields['title']."\"></td></tr>
        <tr><td bgcolor=#eeeeee align=right valign=top>Block Content:</td><td><textarea name=content cols=80 rows=20>".$res->fields['content']."</textarea></td></tr>
        </table>
        <input type=hidden name=blk_id value=\"$blk_id\">
        <input type=submit class=search value=\"Update\">
    </form>
    </td>
    </tr>
    </table>
\n";

	}	

}

#
# getUID - gets id of user
#

function getUID($login) {

	global $db;
	
	$res = $db->Execute("select * from blog_users where login='$login'");
	return $res->fields['id'];

}

#
# getUserInfo - gets user data based on ID
#

function getUserInfo($id) {

	global $db;

	$res = $db->Execute("select * from blog_users where id=$id");
        return $res->fields;

}

/* Trackback functions */
//generate rdf for trackback autodiscovery
function tb_rdf() {
	
	global $blogEntry, $blogInfo, $baseurl;

	$rdf = "<!-- //RDF for trackback autodiscovery
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\"
         xmlns:trackback=\"http://madskills.com/public/xml/rss/module/trackback/\">
<rdf:Description
    rdf:about=\"".htmlentities($baseurl."/archive.php?blogid=".$blogInfo->blogId."&pid=".$blogEntry->entryId)."\"
    dc:identifier=\"".htmlentities($baseurl."/archive.php?blogid=".$blogInfo->blogId."&pid=".$blogEntry->entryId)."\"
    dc:title=\"$blogInfo->blogTitle\"
    trackback:ping=\"$baseurl/tb.php/$blogEntry->entryId\" />
</rdf:RDF>
-->
";

	return $rdf;
	
}


// Send a trackback to another server
function send_tb_ping($tb_arr) {
    // import the http class
    include_once("class.HttpClient.php");

    // Make sure the excerpt is short enough
    $body = strip_tags($tb_arr['excerpt']);
    $tb_arr['excerpt'] = substr($body,0,255)."...";

    // extract the Trackback url
    $tb_url = $tb_arr['tb_url'];

    // Did we get a trackback url?
    if (!$tb_url) {
        // Couldn't find a Trackback url. Give up.
        echo "Can't get trackback URL";
        return;
    }
    // remove it from the array
    unset($tb_arr['tb_url']);

    // parse the TB url to get the host and path
    $urlobj = parse_url($tb_url);

	
    // Create the http client object
    $http_client = new HttpClient($urlobj['host']);

    // Post the data
    if ($urlobj['query']){
    	$urlobj['path'].="?".$urlobj['query'];
    }
    $status = $http_client->post($urlobj['path'],$tb_arr);

    if ($status == true) {
        $rsp = $http_client->getContent();
    } else {
        $rsp = "Doh! Status: ".$http_client->getError();
    }
    return $rsp;
}

// Return a list of trackbacks for a particular id
function list_trackbacks($postid) {
    global $db,$conn;

    $sql = "SELECT * FROM blog_trackback WHERE entry_id = $postid";
    $res = $db->Execute($sql);

    // iterate results
    while (!$res->EOF) {
        $list[] = $res->fields;
        $res->MoveNext();
    }

	if (isset($list)){
    	return $list;
    }else{
    	return null;
    }	

}

// I don't like how the PHP count() function returns 1 if
// you pass it a scalar. So this is my custom function that
// will return 0 if the argument isn't an array.
function array_count($arr) {
    if (!is_array($arr)) {
        return 0;
    }

    return count($arr);
}

// Return a raw count of how many trackbacks an entry has.
function tb_count($id) {
    $list = list_trackbacks($id);

    return array_count($list);
}

// Display HTMLized list of trackbacks
function tb_list($id) {
    global $baseurl,$blogid;
    $list = list_trackbacks($id);

    $tburl = $baseurl . '/tb.php/' . $id;

    ?>
    <div class="trackbacks">
    <h4>Trackbacks</h4>
    <p>The Trackback URL for this entry is:
    <?=$tburl ?>
    </p>
    <ul>
    <?php 
    if (!array_count($list)) {
        // No trackbacks
        ?>
        <li>
        <p>
        No trackbacks.
        </p>
        </li>
        <?php 
    } else {

        while (list($row,$data) = each($list)) {
 	    $tb_id = $data['tb_id'];
            $post_title = $data['title'];
            $excerpt = $data['excerpt'];
            $url = $data['url'];
            $blogname = $data['blog_name'];
            $added = $data['added'];
	    $ip = $data['ip'];
	    
            if ($blogname) {
                $blogname = " from " . $blogname;
            }

            ?><li>
            <a href="<?=$url ?>"><?=$post_title ?></a>
    <cite><?=$blogname ?> <?=date("r",strtotime($added)) ?></cite> 
<? if(isAdmin()): ?>
(IP: <?=$ip?> <small>[<a href="admin.php?blogid=<?=$blogid?>&adm=ban&ip=<?=$ip?>" onClick="return confirm('Are you sure you want to ban this IP?');">ban</a>][<a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=tb&tb_id=<?=$tb_id?>&op=tb_del" onClick="return confirm('Are you sure you want to delete this?');">delete</a>]</small>)
<? endif; ?>
            <blockquote cite="<?=$url ?>" title="Quoted from
<?=$blogname ?>">
            <?=$excerpt?>
            </blockquote>
            </li>
            <?php 
        }
    }
    print "</ul></div>\n";

}

// Display RSSized list
function tb_rss($id) {
    $list = list_trackbacks($id);

}

// Fetch urls in entry and attempt to auto-discover a TB link
function tb_autodiscover($text) {

	include_once("class.HttpClient.php");
	$tb_urls = array();
	#if manual is set, use that and ignore autodiscovers, otherwise scan text.
	if ($_REQUEST['man_tb']){
		$man_tbs = explode ("\n",$_REQUEST['man_tb']);
		foreach($man_tbs as $url){
			#echo "URL:<br>$url<br>";
			array_push($tb_urls,$url);
		}
	}
	
	preg_match_all("/(((http(s?):\/\/)|(www\.))([\-\_\w\.\/\#\?\+\&\=\%\;]+))/i",$text,$matches);
	
	foreach($matches[0] as $url) {
		#echo "URL:<br>$url<br>";
		$contents = HttpClient::quickGet($url);
		if(preg_match_all("/(<rdf:RDF.*?<\/rdf:RDF>)/si",$contents,$m)) {
			foreach($m[0] as $rdf) {
				preg_match("/dc:identifier=\"([^\"]+)\"/",$rdf,$m2);
				if(unhtmlentities($m2[1]) == $url) {
					if(preg_match("/trackback:ping=\"([^\"]+)\"/",$rdf,$m3)) {
						if(!in_array($m3[1],$tb_urls)) {
							array_push($tb_urls,$m3[1]);
						}
					}
				}
			}
		}
	}
	return $tb_urls;

}

function tblink($id,$date) {
    $tblist = list_trackbacks($id);
    $count = array_count($tblist);
    $post_link = get_simple_link($date);

    $msg = "<a href=\"$post_link\">Trackbacks($count)</a>";

    return $msg;
}

/* Pingback functions */


// Return a list of pingbacks for a particular id
function list_pingbacks($postid) {
    global $db,$conn,$blogid;

    $sql = "SELECT * FROM blog_pingback WHERE entry_id = $postid";
    $res = $db->Execute($sql);

    // iterate results
    while (!$res->EOF) {
        $list[] = $res->fields;
        $res->MoveNext();
    }
	if (isset($list)){
    	return $list;
    }else{
    	return null;
    }	

}

// Return a raw count of how many pingbacks an entry has.
function pb_count($id) {
    $list = list_pingbacks($id);

    return array_count($list);
}


// Display HTMLized list of pingbacks
function pb_list($id) {
    global $baseurl,$blogid;
    $list = list_pingbacks($id);

    ?>
    <div class="pingbacks">
    <h4>Pingbacks</h4>
    <ul>
    <?php 
    if (!array_count($list)) {
        // No pingbacks
        ?>
        <li>
        <p>
        No pingbacks.
        </p>
        </li>
        <?php 
    } else {

        while (list($row,$data) = each($list)) {
            $blogname = $data['blog_name'];
            $url = $data['url'];
            $added = $data['added'];

            ?><li>from
            <a href="<?=$url ?>"><cite><?=$blogname ?></cite></a>
            on <?=date("r",strtotime($added)) ?></cite>
            </li>
            <?php 
        }
    }
    print "</ul></div>\n";

}

// Display RSSized list
function pb_rss($id) {
    $list = list_pingbacks($id);

}

function pblink($id,$date) {
    $pblist = list_pingbacks($id);
    $count = array_count($pblist);
    $post_link = get_simple_link($date);

    $msg = "<a href=\"$post_link\">Pingbacks($count)</a>";

    return $msg;
}

function pb_autodiscover($text) {

    include_once("class.HttpClient.php");

	$pb_urls = array();

	#parse urls in entry
    preg_match_all("/(((http(s?):\/\/)|(www\.))([\-\_\w\.\/\#\?\+\&\=\%\;]+))/i",$text,$matches);

	#for each url
    foreach($matches[0] as $url) {
		#get url
		$data = parse_url($url);
		$http = new HttpClient($data['host']);
        if($http->get($data['path']."?".$data['query'])) {

			#examine headers for pingback url
			$pburl = $http->getHeader("X-Pingback");
				if($pburl != '') {
					if(!array_key_exists($url,$pb_urls)) {
						$pb_urls[$url] = unhtmlentities($pburl);
						continue;
					}
				}

			$contents = $http->getContent();

        	if(preg_match('/<link rel=\"pingback\" href=\"([^"]+)\"/si',$contents,$m)) {
				if(!array_key_exists($url,$pb_urls)) {
					$pb_urls[$url] = unhtmlentities($m[1]);
				}
        	}
		}
    }

    return $pb_urls;


}

function send_pingback($pb_arr) {

	$f=new xmlrpcmsg('pingback.ping',
                array(new xmlrpcval($pb_arr['url'],'string'),
                    new xmlrpcval($pb_arr['target_uri'],'string')));
	$data = parse_url($pb_arr['pb_url']);
  $c=new xmlrpc_client($data['path'], $data['host'], 80);
  $c->setDebug(0);
  $r=$c->send($f);
  if ($r->val) {
      $v=xmlrpc_decode($r->value());
      if (!$r->faultCode()) {
        $result['message'] =  "<p class=\"rpcmsg\">";
        $result['message'] = $result['message'] .  $v . "<br />\n";
        $result['message'] = $result['message'] . "</p>";
      } else {
        $result['err'] = $r->faultCode();
        $result['message'] =  "<!--\n";
        $result['message'] = $result['message'] . "Fault: ";
        $result['message'] = $result['message'] . "Code: " . $r->faultCode();
        $result['message'] = $result['message'] . " Reason '" .$r->faultString()."'<BR>";
        $result['message'] = $result['message'] . "-->\n";
      }

      // Checking $act will prevent us from creating spurious output when
      // called from the Blogger API functions.
     
        return $result['message'];
     
  }	

  return "success";

}

function now() {
    $date = date("Y-m-d H:i:s",time());
    return $date;
}


function do_pings($entryID) {

	global $blogid,$btitle,$baseurl,$db;

	if($_REQUEST['ping'] == 1) {
          include("./weblogrpc.php");
    	}

    	if($_REQUEST['tb'] == 1) {
        	$tb_urls = tb_autodiscover(do_smilies($_REQUEST['body']));
        	echo "looking for trackbacks...<br>";
				#print_r($tb_urls);

            foreach($tb_urls as $tbu) {

            	echo "trying $tbu<br>";
                $tb_arr['tb_url'] = $tbu;
                $tb_arr['url'] = $baseurl."/archive.php?blogid=$blogid&pid=".$entryID;
                $tb_arr['blog_name'] = stripslashes($btitle);
                $tb_arr['excerpt'] = stripslashes($_REQUEST['body']);
                $tb_arr['title'] = stripslashes($_REQUEST['etitle']);

                $resp = send_tb_ping($tb_arr);
                echo "trackback: ".$resp."<br>\n";
            }
     }

     if($_REQUEST['pb'] == 1) {
            $pb_urls = pb_autodiscover(do_smilies($_REQUEST['body']));

            include_once("xmlrpc.inc");
            foreach($pb_urls as $key => $val) {
                $pb_arr['pb_url'] = $val;
                $pb_arr['target_uri'] = $key;
                $sql = "SELECT * from blog_entries where blog_entry_id=".$entryID;
                $r = $db->Execute($sql);
                $pb_arr['url'] = $baseurl."/archive.php?blogid=$blogid&pid=".$r->fields['blog_entry_id'];
                $pb_arr['blog_name'] = $btitle;
                $pb_arr['excerpt'] = $_REQUEST['body'];
                $pb_arr['title'] = $_REQUEST['etitle'];

                $resp = send_pingback($pb_arr);
                echo "pingback: $resp<br>\n";
            }
     }	

}

#
# ip_ban - inserts an IP into the ban table
#
function ip_ban($ip) {

	global $db;

	$num="(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])";

	if (!preg_match("/^$num\\.$num\\.$num\\.$num$/", $ip)) {
		return "<b>$ip is not a valid IP Address!</b><br>\n";
	}

	if(isAdmin()) {
		$sql = "select * from blog_ip_blacklist where ip='$ip'";
		$res = $db->Execute($sql);
		if($res->RecordCount() == 0) {
			$sql = "insert into blog_ip_blacklist (ip) values ('$ip')";
			$db->Execute($sql);
			$mesg = "<b>IP $ip banned!</b>\n";
		} else {
			$mesg = "<b>IP $ip already banned!</b>\n";	
		}
	} else {
		$mesg = "<b>Only the superuser can ban IPs!</b><br>\n";
	}

	return $mesg;
}

#
# ban_check - check if ip is banned
#
function ban_check($ip) {

	global $db;
	
	$sql = "select * from blog_ip_blacklist where ip='$ip'";
	$res = $db->Execute($sql);

	if($res->RecordCount() > 0) {
		echo "<br><br><center><b>Your IP address ($ip) has been banned from accessing this site</b></center>\n";
		exit(0);
	}
}

function filter_comment() {

	global $db;

	$trap = false;
	$term = '';
	
	$sql = "select term from blog_spam where field_id=".COMMENT_NAME;
	$res = $db->Execute($sql);

	while(!$res->EOF) {
		if(preg_match("/".$res->fields['term']."/",$_REQUEST['cname'])) {
			$trap = true;
			$term = $res->fields['term'];
			break;
		}
		$res->MoveNext();
	}
	
	if(!$trap) {

		$sql = "select term from blog_spam where field_id=".COMMENT_BODY;
	        $res = $db->Execute($sql);

	        while(!$res->EOF) {
			if(preg_match("/".$res->fields['term']."/",$_REQUEST['comment'])) {
	                        $trap = true;
				$term = $res->fields['term'];
	                        break;
	                }
	                $res->MoveNext();
	        }
	}

	if($trap) {
		echo "<b>The term \"$term\" is not allowed in comments</b><br>\n";
	}

	return !$trap;
	
}

//hasFlickrAccount
function hasFlickrAccount($login) {

	global $db;

	$sql = "select * from blog_flickr where user_id=".getUID($login);
	$res = $db->Execute($sql);

	if($res->RecordCount() > 0) {
		return true;
	} else {
		return false;
	}
	
}

ban_check($_SERVER['REMOTE_ADDR']);

?>

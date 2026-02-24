<?php

#############################################################
#
# global variables section
#
# $blogurl - URL to your main blog page
# $baseurl - Base URL of MyPHPblog directory
# $basepath - path to MyPHPblog on the filesystem
# $host - host machine of your database
# $db - name of the database
# $user -  your userid for the database
# $passwd - your password for the database
# $dbtype - type of database you are using
# $anon - name displayed for anonymous comment posters
# $ratename = what you want to call your rating points (I use Karma)
# $limit - the number of entries to display
# $timeout - time in minutes for an RSS feed to live in cache
# $use_weblog_rpc - register changes with weblogs.coma
# $enable_trackback - use trackback
# $enable_pingback - use pingback
# $enable_smilies - use smilie emoticons
# $enable_flickr - be able to add photos from a flickr account into entries
# $safe_comments - attempt to clean up HTML in comments to keep out malicious code
# $comment_win - open comments in new window
#
#############################################################

$blogurl = "localhost/simplog/index.php"; //change this
$baseurl = "/simplog";  //change this - omit the trailing slash
$basepath = "/Library/WebServer/Documents/simplog";  //change this

$host = "localhost";
$dbase = "blog";
$user = "blog";
$passwd = "blog";
$dbtype = "mysql";  // if using PostgreSQL, set to 'postgres'

$anon = "Anonymous";
$ratename = "Karma";
$limit = 5;
$timeout = 1; //cache timeout, in minutes

//date format for blog entries
$dateformat = "m/d/Y h:i:s a";

// setting these to 1 may cause long load times when users save entries
$use_weblog_rpc = 0; //ping weblogs.com
$enable_trackback = 1; //use trackback
$enable_pingback = 1; //use pingback
$enable_smilies = 1; //use smilies
$enable_flickr = 1; //user flickr images in posts

$safe_comments = 1; //strip out unsafe HTML in user comments(recommended)

$comment_win = 1; //pop comments up in a new window

?>

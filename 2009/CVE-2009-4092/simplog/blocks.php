<?php 
# Block types
#	1 categories
#	2 rss feeds
#	3 recent entries
#	4 archives by month
#	5 
#	6
#	7 search
#	8 login
#	9 calendar
#	10 XML feeds
#	11 Recent Trackbacks
#	12 Recent Comments

if(!is_numeric($blogid)) {
	$blogid = $_REQUEST['blogid'];

	if(!is_numeric($blogid)) {
		$res = $db->Execute("select * from blog_list");
		$blogid = $res->fields['blog_id'];
	}
}

$sql = "select * from blog_blocks where blog_id=$blogid order by blk_order";
$res = $db->Execute($sql);
$i = 1;
while(!$res->EOF) {

	echo "<!--block $i--><table width=100%>\n";
	if($res->fields['blk_type_id'] != 9) {
		echo "<tr>
			<td class=header><b>".$res->fields['title']."</b></td>
		</tr>\n";
	}

	echo "		<tr>\n";

	if($res->fields['blk_type_id'] != 10) {
		echo "			<td class=small>\n";
	} else {
		echo "			<td>\n";
	}

	if($res->fields['blk_type_id'] == 1) {
		$sql = "SELECT * from blog_categories where blog_id=$blogid order by cat_name";

		$res2 = $db->Execute($sql);
		while(!$res2->EOF) {
		    echo "<a href=\"archive.php?blogid=$blogid&cid=".$res2->fields['cat_id']."\">".$res2->fields['cat_name']."</a><br>\n";
    		$res2->MoveNext();
		}	

	} elseif($res->fields['blk_type_id'] == 2) {
	
		$res2 = $db->Execute("select * from blog_rss where rss_id=".$res->fields['rss_id']);

		$rss = get_feed($res->fields['rss_id'],$res2->fields['url']);

		for($y=0;$y<count($rss->items);$y++) {
			if($rss->items[$y]['title'] == "") {
				$rss->items[$y]['description'] = unhtmlentities($rss->items[$y]['description']);
	            $rss->items[$y]['title'] = substr(strip_tags($rss->items[$y]['description']),0,20)."...";
	        }

			if($rss->items[$y]['link'] == "") {
				$rss->items[$y]['link'] = $rss->items[$y]['guid'];
			}
			
			echo "<li><a href=\"".$rss->items[$y]['link'] ."\" target=_new>". $rss->items[$y]['title'] . "</a>\n";
		}
	} elseif($res->fields['blk_type_id'] == 3) {

        $blogInfo =& new BlogInfo($blogid);
        if ( $blogInfo->isUserAuthorized() ) {
            $blogEntries = $blogInfo->getLastNEntries(8);
    
            foreach ($blogEntries as $blogEntry) {
                if(!preg_match("/\w/",$blogEntry->entryTitle)) {
                    $blogEntry->entryTitle = substr(strip_tags($blogEntry->entryBody),0,20)."...";
                }
			echo "<a href=\"archive.php?blogid=$blogid&pid=".$blogEntry->entryId."\">".$blogEntry->entryTitle."</a><br>";
            }
        }
	} elseif($res->fields['blk_type_id'] == 4) {

		$blogInfo =& new BlogInfo($blogid);
        $dateList = $blogInfo->getYearMonthOfEntries();

        foreach ($dateList as $key => $value) {
                list($year, $month) = split("-", $key,2);
				echo "<a href=archive.php?blogid=$blogid&y=$year&m=$month>".getThisMo($month)." $year<br>\n";
	#			$mo = $match[2];
			}


	} elseif($res->fields['blk_type_id'] == 5) {
		//filter out naughty code....
		$res->fields['content'] = preg_replace("/(exec|system|phpinfo|passthru)/","print",$res->fields['content']);
		eval(stripslashes($res->fields['content']));
	} elseif($res->fields['blk_type_id'] == 6) {
		echo $res->fields['content'];
	} elseif($res->fields['blk_type_id'] == 7) {
		echo "<div align=center>
		<form action=\"archive.php\" method=POST>
		<input type=hidden name=blogid value=\"$blogid\">
		<input type=hidden name=act value=\"search\">
		<input type=text class=search2 name=keyw><br><input class=search type=submit value=\"Search\">
		</form>
		</div>\n";
	} elseif($res->fields['blk_type_id'] == 8) {
		if(isLoggedIn()) {
			echo "Hello ".$_SESSION['login']."<p>";
			echo "<li><a href=\"$baseurl/edit.php?blogid=$blogid\">Add New Entry</a>\n";
			echo "<li><a href=\"$baseurl/logout.php?blogid=$blogid\">Logout</a>\n";
		} else {
			echo  make_login();
		}
	} elseif($res->fields['blk_type_id'] == 9) {
		$m = date("n",mktime());
		$y = date("Y",mktime());

		echo  mk_Calendar($m,$y,0);
	} elseif($res->fields['blk_type_id'] == 10) {
		echo "<table><tr><td>\n";
		echo "<div id=css-buttons2><p><a class=\"css-button2 rss\" href=\"$baseurl/rss.php?blogid=$blogid\" title=\"RSS v0.9x\"><span>RSS</span> 0.9x</a></p>\n
		<p><a class=\"css-button2 rss\" href=\"$baseurl/rss2.php?blogid=$blogid\" title=\"RSS v2.0\"><span>RSS</span> 2.0</a></p>\n
		<p><a class=\"css-button2 atom\" href=\"$baseurl/atom.php?blogid=$blogid\" title=\"Atom v0.2\"><span>Atom</span> 0.3</a></p>\n";
		echo "</div></td></tr></table>\n";
    
    } elseif($res->fields['blk_type_id'] == 11) {
		$sql = "SELECT * from blog_trackback, blog_entries where entry_id=blog_entry_id AND blog_id=$blogid AND NOT (url LIKE '$baseurl%' AND url LIKE '%blogid=$blogid%') order by added desc limit 10 ";

		$res2 = $db->Execute($sql);

		while(!$res2->EOF) {
			$test_url = $res2->fields['url'];
		    echo "<p><a href=\"$test_url\">".$res2->fields['blog_name']."</a> on <a href='$baseurl/archive.php?blogid=$blogid&pid=".$res2->fields['entry_id']."'>".$res2->fields['title']."</a></p>\n";
			
    		$res2->MoveNext();
		}
    } elseif($res->fields['blk_type_id'] == 12) {
		$sql = "SELECT * from blog_comments, blog_entries where eid=blog_entry_id AND bid=$blogid order by blog_comments.date desc limit 10 ";

		$res2 = $db->Execute($sql);

		while(!$res2->EOF) {
		    echo "<p>".$res2->fields['name']." on <a href='$baseurl/archive.php?blogid=$blogid&pid=".$res2->fields['eid']."'>".$res2->fields['title']."</a></p>\n";
			
    		$res2->MoveNext();
		}
    }

	echo "
			</td>
		</tr>
	</table><p>\n";
	$i++;
	$res->MoveNext();
}

?>

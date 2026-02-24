<table width="100%">
<tr>
<td valign="top" width="33%">
<b>IP/Spam Controls</b>
<ul>
	<li><a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=comment">Comment Filters</a>
	<li><a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=tb">Trackback Filters</a>
	<li><a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=white">Trackback Whitelist</a>
	<li><a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=ip">IP Ban List</a>
</ul>
</td>
<td valign="top" align="center">
<?php

	if($_REQUEST['section'] == 'ip') {

		if($_REQUEST['op'] == 'add') {
			echo ip_ban($_REQUEST['ip']);
		} else if($_REQUEST['op'] == 'del') {
			$sql = "delete from blog_ip_blacklist where ip='".$_REQUEST['ip']."'";
			$db->Execute($sql);
			echo "<b>IP ".$_REQUEST['ip']." deleted from ban list!</b><br>\n";
		}
		
?>
	<form name="filter" action="admin.php" method="POST">
        <input type="hidden" name="blogid" value="<?=$blogid?>">
	<input type="hidden" name="adm" value="spam">
        <input type="hidden" name="section" value="ip">
        <input type="hidden" name="op" value="add">
	<table>
	<tr>
        <td colspan="2">Ban a new IP Address:</td>
        </tr>
        <tr>
        <td><input type="text" name="ip" value="" size="16" maxlength="16"></td>
        <td><input type="submit" value="Add"></td>
        </tr>
	<tr>
	<td class="header">Banned IP Addresses</td>
	<td class="header">Delete</td>
	</tr>

<?php		
		$sql="select * from blog_ip_blacklist";
		$res = $db->Execute($sql);
		$count = 0;
		while(!$res->EOF) {
	 		if($count % 2 == 0) {
                                 echo "<tr class='lightrow'>\n";
                        } else {
                                 echo "<tr class='darkrow'>\n";
                        }
			echo "<td>".$res->fields['ip']."</td>\n";
			echo "<td align=\"center\"><a href=\"admin.php?adm=spam&section=ip&ip=".$res->fields['ip']."&blogid=".$_REQUEST['blogid']."&op=del\" onClick=\"return confirm('Are you sure you want to delete this IP?');\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td>\n";
			echo "</tr>\n";
			++$count;
			$res->MoveNext();
		}

		if($count == 0) {
	                echo "<tr><td colspan=\"2\"><b>No Banned IPs</td></tr>\n";
                }
		
		echo "</table>\n";
	} else if($_REQUEST['section'] == 'white') {

                if($_REQUEST['op'] == 'add') {
                        $sql = "insert into blog_tb_whitelist (host) values ('".$_REQUEST['host']."')";
			$db->Execute($sql);
                } else if($_REQUEST['op'] == 'del') {
                        $sql = "delete from blog_tb_whitelist where id='".$_REQUEST['hid']."'";
                        $db->Execute($sql);
                        echo "<b>Host ".$_REQUEST['host']." deleted from whitelist!</b><br>\n";
			
                }

?>
        <form name="filter" action="admin.php" method="POST">
        <input type="hidden" name="blogid" value="<?=$blogid?>">
        <input type="hidden" name="adm" value="spam">
        <input type="hidden" name="section" value="white">
        <input type="hidden" name="op" value="add">
        <table>
        <tr>
        <td colspan="2">Whitelist a new host:</td>
        </tr>
        <tr>
        <td><input type="text" name="host" value="" size="16" maxlength="16"></td>
        <td><input type="submit" value="Add"></td>
        </tr>
        <tr>
        <td class="header">Whitelisted Hosts</td>
        <td class="header">Delete</td>
        </tr>

<?php
		$sql="select * from blog_tb_whitelist";
                $res = $db->Execute($sql);
                $count = 0;
                while(!$res->EOF) {
                        if($count % 2 == 0) {
                                  echo "<tr class='lightrow'>\n";
                         } else {
                                  echo "<tr class='darkrow'>\n";
                         }
                          echo "<td>".$res->fields['host']."</td>\n";
                          echo "<td align=\"center\"><a href=\"admin.php?adm=spam&section=white&hid=".$res->fields['id']."&blogid=".$_REQUEST['blogid']."&op=del\" onClick=\"return confirm('Are you sure you want to delete this host?');\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td>\n";
                          echo "</tr>\n";
                          ++$count;
                        $res->MoveNext();
                  }

                  if($count == 0) {
                          echo "<tr><td colspan=\"2\"><b>No Whitlisted Hosts</td></tr>\n";
                  }

                  echo "</table>\n";
	
	} else if($_REQUEST['section'] == 'tb') {
		if($_REQUEST['op'] == 'add') {

			$sql = "insert into blog_spam (field_id,term) values (".$_REQUEST['field'].",'".$_REQUEST['term']."')";
			$db->Execute($sql);

			echo "<b>Term ".$_REQUEST['term']." added!</b><br>\n";
			
		} else if($_REQUEST['op'] == 'del') {
			$sql = "delete from blog_spam where id=".$_REQUEST['tid'];
			$db->Execute($sql);

			echo "<b>Term ".$_REQUEST['term']." deleted!</b><br>\n";
		} else if($_REQUEST['op'] == 'tb_del') {
			$sql = "delete from blog_trackback where tb_id=".$_REQUEST['tb_id'];
                        $db->Execute($sql);

                        echo "<b>Trackback deleted!</b><br>\n";
			echo "<a href=\"".$_SERVER['HTTP_REFERER']."\">Go Back</a><br>\n";
		}
?>
	<form name="filter" action="admin.php" method="POST">
	<input type="hidden" name="blogid" value="<?=$blogid?>">
	<input type="hidden" name="adm" value="spam">
	<input type="hidden" name="section" value="tb">
	<input type="hidden" name="op" value="add">
	<table>
		<tr>
		<td colspan="3">Add a new term to the filter:</td>
		</tr>
		<tr>
		<td>
		<select name="field">
			<option value="<?=TB_URL?>">TB URL</option>
			<option value="<?=TB_BLOG_NAME?>">TB Blog Name</option>
			<option value="<?=TB_EXCERPT?>">TB Excerpt</option>
		</select>
		</td>
		<td><input type="text" name="term" value="" size="32" maxlength="128"></td>
		<td><input type="submit" value="Add"></td>
		</tr>
	<tr><td colspan="3" align="right"><a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=filter&op=tbcheck">Run filters against all trackbacks</a></td></tr>
		<tr>
		<td class="header">Field Type</td>
		<td class="header">Term</td>
		<td class="header">Delete</td>
		</tr>
<?
		$sql="select s.*, f.field from blog_spam s, blog_spam_field f where s.field_id in (".TB_URL.",".TB_BLOG_NAME.",".TB_EXCERPT.") and s.field_id=f.id order by s.field_id, s.term";
                $res = $db->Execute($sql);
		$count = 0;
                while(!$res->EOF) {
			if($count % 2 == 0) {
				echo "<tr class='lightrow'>\n";
			} else {
				echo "<tr class='darkrow'>\n";
			}
			echo "<td>".$res->fields['field']."</td>\n";
			echo "<td>".$res->fields['term']."</td>\n";
			echo "<td align=\"center\"><a href=\"admin.php?adm=spam&section=tb&tid=".$res->fields['id']."&blogid=".$_REQUEST['blogid']."&op=del\" onClick=\"return confirm('Are you sure you want to delete this term?');\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td>\n";
			echo "</tr>\n";
                        $res->MoveNext();
			++$count;
                }

		if($count == 0) {
			echo "<tr><td colspan=\"3\"><b>No Terms Found!</td></tr>\n";
		}
		echo "</table>\n";
		echo "</form>\n";
	} else if($_REQUEST['section'] == 'comment') {
		 if($_REQUEST['op'] == 'add') {

                         $sql = "insert into blog_spam (field_id,term) values (".$_REQUEST['field'].",'".$_REQUEST['term']."')";
                         $db->Execute($sql);

                         echo "<b>Term ".$_REQUEST['term']." added!</b><br>\n";

                 } else if($_REQUEST['op'] == 'del') {
                         $sql = "delete from blog_spam where id=".$_REQUEST['tid'];
                         $db->Execute($sql);

                         echo "Term ".$_REQUEST['term']." deleted!</b><br>\n";
                 }
?>
        <form name="filter" action="admin.php" method="POST">
        <input type="hidden" name="blogid" value="<?=$blogid?>">
        <input type="hidden" name="adm" value="spam">
        <input type="hidden" name="section" value="comment">
        <input type="hidden" name="op" value="add">
        <table>
                <tr>
                <td colspan="3">Add a new term to the filter:</td>
                </tr>
                <tr>
	        <td>
                <select name="field">
                <option value="<?=COMMENT_NAME?>">Comment Name</option>
                <option value="<?=COMMENT_BODY?>">Comment Body</option>
                </select>
                </td>
                <td><input type="text" name="term" value="" size="32" maxlength="128"></td>
                <td><input type="submit" value="Add"></td>
                </tr>
	<tr><td colspan="3" align="right"><a href="admin.php?blogid=<?=$blogid?>&adm=spam&section=filter&op=comcheck">Run filters against all comments</a></td></tr>
                <tr>
                <td class="header">Field Type</td>
                <td class="header">Term</td>
                <td class="header">Delete</td>
                </tr>
<?
		$sql="select s.*, f.field from blog_spam s, blog_spam_field f where s.field_id in (".COMMENT_NAME.",".COMMENT_BODY.") and s.field_id=f.id order by s.field_id, s.term";
                $res = $db->Execute($sql);
                $count = 0;
                while(!$res->EOF) {
                        if($count % 2 == 0) {
                                echo "<tr class='lightrow'>\n";
                        } else {
                                echo "<tr class='darkrow'>\n";
                        }
                        echo "<td>".$res->fields['field']."</td>\n";
                        echo "<td>".$res->fields['term']."</td>\n";
	                echo "<td align=\"center\"><a href=\"admin.php?adm=spam&section=comment&tid=".$res->fields['id']."&blogid=".$_REQUEST['blogid']."&op=del\" onClick=\"return confirm('Are you sure you want to delete this term?');\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td>\n";
			echo "</tr>\n";
			$res->MoveNext();
                        ++$count;
                }
                if($count == 0) {
                      echo "<tr><td colspan=\"3\"><b>No Terms Found!</td></tr>\n";
		}
		echo "</table>\n";
		echo "</form>\n";			
	} else if($_REQUEST['section'] == "filter") {

		$caught = array();
		
		if($_REQUEST['op'] == 'comcheck') {

			$comment_name = array();
			$comment_body = array();
			$comdata = array();
			
			$sql = "select * from blog_spam where field_id in (".COMMENT_NAME.",".COMMENT_BODY.")";
			$res = $db->Execute($sql);

			while(!$res->EOF) {
				if($res->fields['field_id'] == COMMENT_NAME) {
					array_push($comment_name,$res->fields['term']);
				} else if($res->fields['field_id'] == COMMENT_BODY) {
	                	        array_push($comment_body,$res->fields['term']);
	                        }
				$res->MoveNext();
			}
			
			$sql = "select * from blog_comments";
			$res = $db->Execute($sql);

			while(!$res->EOF) {

				foreach($comment_name as $term) {
					if(preg_match("/$term/i",$res->fields['name'])) {
						$res->fields['name'] = preg_replace("/$term/i","<span style=\"color: red\">$term</span>",$res->fields['name']);

						array_push($caught,$res->fields['id']);
						$comdata[$res->fields['id']]['name'] = $res->fields['name'];
						$comdata[$res->fields['id']]['comment'] = $res->fields['comment'];
					}
				}
				
				foreach($comment_body as $term) {
					
                                	if(preg_match("/$term/i",strip_tags($res->fields['comment']))) {
						if(!in_array($res->fields['id'],$caught)) {
							$res->fields['comment'] = preg_replace("/$term/i","<span style=\"color: red\">$term</span>",$res->fields['comment']);
							array_push($caught,$res->fields['id']);
							$comdata[$res->fields['id']]['name'] = $res->fields['name'];
	                                                $comdata[$res->fields['id']]['comment'] = $res->fields['comment'];
		                                }
					}
				}

				$res->MoveNext();
			}
		
			if(sizeof($caught) == 0) {
				echo "No Comment Spam Found!<br>\n";
			} else {	
?>
	<form action="admin.php" method="POST" name="comments">
	<input type="hidden" name="blogid" value="<?=$blogid?>">
	<input type="hidden" name="adm" value="spam">
	<input type="hidden" name="section" value="filter">
	<input type="hidden" name="op" value="comdel">
	<table>
	<tr>
	<td colspan="3"><b>Comments trapped by filter:</b></td>
	</tr>
	<tr>
	<td colspan="3"><input type=submit value="Delete Selected" class="search">
	</tr>
	<tr>
	<td class="header"><input type="checkbox" name="all" onClick="checkAll(this);"></td>
	<td class="header">Name</td>
	<td class="header">Comment</td>
	</tr>

<?
				$count = 0;
				foreach($caught as $com) {
					if($count % 2 == 0) {
						echo "<tr class=\"lightcell\">\n";
					} else {
						echo "<tr class=\"darkcell\">\n";
					}
					echo "<td><input type=\"checkbox\" name=\"comment[]\" value=\"$com\"></td>\n";
					echo "<td>".$comdata[$com]['name']."</td><br>\n";
					echo "<td>".$comdata[$com]['comment']."</td><br>\n";
					echo "</tr>\n";
				}
				echo "<tr>
			        <td colspan=\"3\"><input type=submit value=\"Delete Selected\" class=\"search\">
			        </tr>\n";
				echo "</table>\n</form>\n";
			}
		} else if($_REQUEST['op'] == 'comdel') {
			
			foreach($_REQUEST['comment'] as $cid) {

				$sql = "delete from blog_comments where id=$cid";
				$db->Execute($sql);
				
			}

			echo "<b>Comments deleted!</b><br>\n";
			
		} else if($_REQUEST['op'] == 'tbcheck') {

                        $tb_name = array();
                        $tb_excerpt = array();
			$tb_url = array();
                        $tbdata = array();

                        $sql = "select * from blog_spam where field_id in (".TB_BLOG_NAME.",".TB_EXCERPT.",".TB_URL.")";
                        $res = $db->Execute($sql);

                        while(!$res->EOF) {
                                if($res->fields['field_id'] == TB_BLOG_NAME) {
                                        array_push($tb_name,$res->fields['term']);
                                } else if($res->fields['field_id'] == TB_EXCERPT) {
                                      array_push($tb_excerpt,$res->fields['term']);
				} else if($res->fields['field_id'] == TB_URL) {
                                      array_push($tb_url,$res->fields['term']);
			        }
                                $res->MoveNext();
                        }

                        $sql = "select * from blog_trackback";
                        $res = $db->Execute($sql);
                        while(!$res->EOF) {

				$blog_name = $res->fields['blog_name'];
				$blog_ex = implode(" ",preg_split("/\s+/",$res->fields['excerpt']));
				$blog_url = $res->fields['url'];
				
                                foreach($tb_name as $term) {
                                        if(preg_match("/$term/i",$blog_name)) {

						$blog_name = preg_replace("/$term/i","<span style=\"color: red\">$term</span>",$blog_name);
						
                                                array_push($caught,$res->fields['tb_id']);
                                                $tbdata[$res->fields['tb_id']]['name'] = $blog_name;
						$tbdata[$res->fields['tb_id']]['excerpt'] = $blog_ex;
						$tbdata[$res->fields['tb_id']]['url'] = $blog_url;
                                        }
				}
 
 				foreach($tb_excerpt as $term) {
                                        if(preg_match("/$term/i",strip_tags($blog_ex))) {
                                                if(!in_array($res->fields['tb_id'],$caught)) {
							
							$blog_ex = preg_replace("/$term/i","<span style=\"color: red\">$term</span>",$blog_ex);
							
                                                        array_push($caught,$res->fields['tb_id']);
                                                        $tbdata[$res->fields['tb_id']]['name'] = $blog_name;
                                                        $tbdata[$res->fields['tb_id']]['excerpt'] = $blog_ex;
							$tbdata[$res->fields['tb_id']]['url'] = $blog_url;
                                                }
                                        }
                                }

				foreach($tb_url as $term) {
                                	if(preg_match("/$term/i",strip_tags($blog_url))) {
                                        	if(!in_array($res->fields['tb_id'],$caught)) {
	                                                $blog_url = preg_replace("/$term/i","<span style=\"color: red\">$term</span>",$blog_url);

                                                         array_push($caught,$res->fields['tb_id']);
                                                         $tbdata[$res->fields['tb_id']]['name'] = $blog_name;
                                                         $tbdata[$res->fields['tb_id']]['excerpt'] = $blog_ex;
                                                         $tbdata[$res->fields['tb_id']]['url'] = $blog_url;
                                                }
                                        }
                                }
				
                                $res->MoveNext();
                        }

			if(sizeof($caught) == 0) {
                                echo "No Trackback Spam Found!<br>\n";
                        } else {
?>
		        <form action="admin.php" method="POST" name="trackbacks">
		        <input type="hidden" name="blogid" value="<?=$blogid?>">
		        <input type="hidden" name="adm" value="spam">
		        <input type="hidden" name="section" value="filter">
		        <input type="hidden" name="op" value="tbdel">
		        <table>
			        <tr>
			        <td colspan="4"><b>Trackbacks trapped by filter:</b></td>
			        </tr>
			        <tr>
	  		        <td colspan="4"><input type=submit value="Delete Selected" class="search">
			        </tr>
			        <tr>
			        <td class="header"><input type="checkbox" name="all" onClick="checkAll(this);"></td>
			        <td class="header">Name</td>
			        <td class="header">Excerpt</td>
				<td class="header">URL</td>
			        </tr>
<?
                                $count = 0;
                                foreach($caught as $tb) {
                                        if($count % 2 == 0) {
                                                echo "<tr class=\"lightcell\">\n";
                                        } else {
                                                echo "<tr class=\"darkcell\">\n";
                                        }
                                        echo "<td><input type=\"checkbox\" name=\"trackback[]\" value=\"$tb\"></td>\n";
					echo "<td>".$tbdata[$tb]['name']."</td><br>\n";
                                        echo "<td>".$tbdata[$tb]['excerpt']."</td><br>\n";
					echo "<td>".$tbdata[$tb]['url']."</td><br>\n";
                                        echo "</tr>\n";
                                }
                                echo "<tr>
	                                <td colspan=\"4\"><input type=submit value=\"Delete Selected\" class=\"search\">
                                      </tr>\n";
                                echo "</table>\n</form>\n";
                        }
                } else if($_REQUEST['op'] == 'tbdel') {
                        foreach($_REQUEST['trackback'] as $tid) {
                                $sql = "delete from blog_trackback where tb_id=$tid";
                                $db->Execute($sql);
			}
	
			echo "<b>Trackbacks deleted!</b><br>\n";

	        } 		
	}
	
?>
</td>
</tr>
</table>

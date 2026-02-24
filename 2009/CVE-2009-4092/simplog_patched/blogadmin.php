<?PHP

session_start();
 
require("lib.php");

$uid = getUID($_SESSION['login']);

#if no blog id passed or not a valid integer, set to arbitrary blog in user's acl
if(!$_REQUEST['blogid'] or !is_numeric($_REQUEST['blogid'])) {
    $sql = "SELECT blog_id from blog_acl where user_id=$uid";
    $res = $db->Execute($sql);

    $blogid = $res->fields[blog_id];
} else {
    $blogid = $_REQUEST['blogid'];
}

$blogInfo = new blogInfo($blogid);

auth();

if(!isBlogAdmin($blogid)) {
	header("Location: logout.php\n\n");
	exit(0);
}

include("header.php");

#show_menu();

?>

<script language="JavaScript">

function addNames() {
  mailList = window.document.modblog.elements['acl[]'];
  srcList = window.document.modblog.elements['lusers'];
 
  if (mailList.options[0].text == "No Users Selected") {
    mailList.options[0] = null;
  }
  var len = mailList.length;
  for(var i = 0; i <srcList.length; i++) {
    if ((srcList.options[i] != null) && (srcList.options[i].selected)) {
      //Check if this value already exist in the destList or not
      //if not then add it, otherwise do not add it.
      var found = false;
      for(var count = 0; count <len; count++) {
        if (mailList.options[count] != null) {
          if (srcList.options[i].text == mailList.options[count].text) {
            found = true;
            break;
          }
        }
      }
      if (found != true) {
        mailList.options[len] = new Option(srcList.options[i].text);
		mailList.options[len].value = srcList.options[i].value;
        len++;
        }
      }
   }
}
 
function removeNames() {
  var minusList  = window.document.modblog.elements['acl[]'];
  var len = minusList.options.length;
  for(var i = (len-1); i >= 0; i--) {
    if ((minusList.options[i] != null) && (minusList.options[i].selected == true)) {
      minusList.options[i] = null;
    }
  }
 
  if(minusList.options.length == 0) {
          minusList.options[0] = new Option("No Users Selected");
          minusList.options[0].value = "null";
  }
}

function selectAll() {
	var acl = window.document.modblog.elements['acl[]'];
	var len = acl.options.length;
	for(var i = (len-1); i >= 0; i--) {
	    if (acl.options[i].text != "No Users Selected"){
			acl.options[i].selected = true;
		}
	}
	return true;
}

</script>

<p>
<?php 

$sql = "SELECT * from blog_list where blog_id=$blogid";
$res = $db->Execute($sql);

$btitle = $res->fields['title'];


if($_REQUEST['op'] == "save") {

		$sql = "delete from blog_acl where blog_id=$blogid";
        $res = $db->Execute($sql);

        for($i=0; $i<count($_REQUEST['acl']); $i++) {
            $sql = "SELECT id from blog_users where login='".$_REQUEST['acl'][$i]."'";
            $res = $db->Execute($sql);

            $sql = "insert into blog_acl (user_id,blog_id) values (".$res->fields['id'].",$blogid)";
            $res = $db->Execute($sql);
        }
		echo "<b>Blog ACL Updated!</b><p>\n";

}

?>
<form name=modblog action="blogadmin.php?blogid=<?=$blogid?>&op=save" method=post>
<table width=100%>
<tr><td class=header><b>Add/Edit Users for <?=$btitle?></b></td></tr>
	<tr>
		<td align=center>
					<table>
						<tr>
                        <td>
						All Users<br>
                        <select name="lusers" size=5 multiple>
<?php 
    $sql = "SELECT login,name from blog_users";
        $res = $db->Execute($sql);
        while(!$res->EOF) {
        echo "<option value=\"".$res->fields['login']."\">".$res->fields['name']."\n";
                $res->MoveNext();
        }
?>
						</select>
                        </td>
                        <td valign=middle>
                        <input class=search type=button value="->" onClick="javascript:addNames()"><p>
                        <input class=search type=button value="<-" onClick="javascript:removeNames()">
                        </td>
                        <td><?=$btitle?> ACL<br>
                        <select name="acl[]" size=5 multiple>

<?php 
        $sql = "SELECT user_id from blog_acl where blog_id=".$blogid;
        $res = $db->Execute($sql);
        $count = 0;
        while(!$res->EOF) {
                if(($res->fields['user_id'] == "") and ($count == 0)) {
                        break;
                }
                $sql2 = "select login,name from blog_users where id=".$res->fields['user_id'];
                $res2 = $db->Execute($sql2);
                echo "<option value=\"".$res2->fields['login']."\">".$res2->fields['name']."</option>\n";
                $count++;
                $res->MoveNext();
        }

        if($count == 0) {
                echo "<option value=\"null\">No Users Selected</option>\n";
        }
?>

                        </select>
                        </td>
                        </tr>
						</table>
						<input type=submit class=search value="Save" onClick="return selectAll();"><input class=search type=reset>
			</td>
			</tr>
			</table>
</table>
</form>
<?php 
	include("footer.php");
?>

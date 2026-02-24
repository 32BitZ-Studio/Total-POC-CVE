<?php 
        if($_REQUEST['act'] == "edit") {
            $sql = "SELECT * from blog_template where temp_id=".$_REQUEST['tid'];
            $tid = $_REQUEST['tid'];
            $res = $db->Execute($sql);
            $tname = $res->fields['name'];
            $templ = $res->fields['template'];
            $templ = stripslashes($templ);
 
        } elseif($_REQUEST['act'] == "updtem") {
            #$_REQUEST['tname'] = addslashes($_REQUEST['tname']);
            #$_REQUEST['templ'] = addslashes($_REQUEST['templ']);
            $sql = "UPDATE blog_template set name='".escape($_REQUEST['tname'])."', template='"
                 . escape($_REQUEST['templ'])."' where temp_id=".$_REQUEST['tid'];
 
            $res = $db->Execute($sql);
            echo "<tr><td colspan=2><b>Template Updated</b></td></tr>\n";
        } elseif($_REQUEST['act'] == "addtem") {
             #$_REQUEST['tname'] = addslashes($_REQUEST['tname']);
             #$_REQUEST['templ'] = addslashes($_REQUEST['templ']);
             $sql = "INSERT into blog_template (name,template) values ('".escape($_REQUEST['tname'])."', '". escape($_REQUEST['templ'])."')";
 
             $res = $db->Execute($sql);
             echo "<tr><td colspan=2><b>Template Added</b></td></tr>\n";
        } elseif($_REQUEST['act'] == "deltem") {
            $sql = "DELETE from blog_template where temp_id=".$_REQUEST['tid'];
            $res= $db->Execute($sql);
            echo "<tr><td colspan=2><b>Template Deleted</b></td></tr>\n";
        }
 
    ?>
 
    <table width=100%>
    <tr>
    <td width=50% valign=top>
        <table width=100%>
            <tr>
                <td class=header>
                    <b><?php if($_REQUEST['act'] == "edit"){ echo "Edit"; } else { echo "Add New"; }?> Template</b>
                </td>
            </tr>
	    </table>
        <form action="admin.php" method=POST name=entry>
        Name: <input type=text size=32 name=tname value="<?php if($_REQUEST['act'] == "edit") { echo $tname; } ?>"><p>
        Template:&nbsp;<small>[ <a href="javascript: openMarkers('<?=$baseurl?>');">Template Markers</a> ]</small> <br>
        <textarea name="templ" rows=20 cols=60 wrap=auto><?php if($_REQUEST['act'] == "edit") { echo $templ; } ?></textarea><p>
        <input type=hidden name=act value="<?php if($_REQUEST['act'] == "edit") { echo "updtem"; } else { echo "addtem"; } ?>">
        <input type=hidden name=adm value="tem">
        <?php if($_REQUEST['act'] == "edit") { echo "<input type=hidden name=tid value=\"$tid\">\n"; } ?>
        <input type=hidden name=blogid value="<?=$_REQUEST['blogid']?>">
        <input type=hidden name=remuser value="<?=$_SESSION['login']?>">
        <input class=search type=submit value="<?php if($_REQUEST['act'] == "edit") { echo "Update"; } else { echo "Add"; } ?>">&nbsp;
        <input type=button class=search value="Preview" onClick="javascript: openPrev2();">&nbsp;
        </form>
    </td>
    <td valign=top align=center>
 
        <table width=100%>
        <tr>
        <td class=header colspan=4>
        <b>Available Templates</b>
        </td>
        </tr>
        </table>
 
        <table>
<?php 
 
    $sql = "SELECT * FROM blog_template";
    $res = $db->Execute($sql);
 
    while(!$res->EOF) {
        echo "<tr><td bgColor=\"#eeeeee\" style=\"border:1px solid #999999;\"><b>".$res->fields['name']."</b></td>\n";
        echo "<td bgColor=\"#eeeeee\" style=\"border:3px #999999;\"><a href=\"#\" onClick=\"openPrev3('".$res->fields['temp_id']."','".$_SESSION['login']."');\">Preview</a></td>\n";
        echo "<td bgColor=\"#eeeeee\" style=\"border:3px #999999;\"><A href=\"admin.php?adm=tem&act=edit&tid=".$res->fields['temp_id']."&blogid=".$_REQUEST['blogid']."\"><IMG alt=\"Edit\" title=\"Edit\" src=\"images/edit.gif\" border=0></A></td>\n";
	echo "<td bgColor=\"#eeeeee\" style=\"border:3px #999999;\"><A href=\"admin.php?adm=tem&act=deltem&tid=".$res->fields['temp_id']."&blogid=".$_REQUEST['blogid']."\" onClick=\"return confirm('Are you sure you want to delete this template?');\"><IMG title=\"Delete\" alt=\"Delete\" src=\"images/delete.gif\" border=0></A></td></tr>\n";
        $res->MoveNext();
    }
 
?>
        </table>
 
    </td>
    </tr>
    </table>
 
 
</td></tr>

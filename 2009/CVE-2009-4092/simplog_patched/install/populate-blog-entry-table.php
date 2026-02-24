<?php 

function escape($var) {

        if(!get_magic_quotes_gpc()) {
                $var = addslashes($var);
        }

        return $var;

}


#include("lib.php");
// the $db connection is inherited from upgrad2.php, in which we are included.

/* The basic strategy:
    For each item in blog_list
        copy entry into blog_entry table from blog_TABLENAME
        drop table blog_TABLENAME if no errors occured.
*/
$getBlogListSQL = "select * from blog_list";
$res = $db->Execute($getBlogListSQL);
while (!$res->EOF) {
    $blogId = $res->fields['blog_id'];
    $tableName = $res->fields['table_name'];

    /* although it would be possible to do this with one really complex
       SQL statement, with maybe a temporary table or two, I'm going to
       try and keep this allin PHP land for the sake of portability. */
    // next step is to start grabbing the blog entries from this blog,
    // and create new entries in the blog_entry table. I can't use the
    // BlogInfo or BlogEntry classes, as they will only work with
    // the consolidated blog_entry table.
    $oldEntriesSQL = "select * from blog_$tableName";
    $entriesRes = $db->Execute($oldEntriesSQL);
    while (!$entriesRes->EOF) {
        // take each entry, insert into blog_entry table.
        $compatEntryId = $entriesRes->fields['id'];
        $body = $entriesRes->fields['body'];
        $body = escape($body);
        $body = ereg_replace("'","<tick>",$body);
        $date = $entriesRes->fields['date'];
	// need to rationalize the 'date' field a bit...
        $time = $db->UnixTimeStamp ($date);
        $date = date ("Y-m-d h:i:s", $time);
        $userid = $entriesRes->fields['userid'];
        $title = $entriesRes->fields['title'];
        $title = escape($title);
        $title = ereg_replace("'","<tick>",$title);
        $karma = $entriesRes->fields['karma'];
        $format = $entriesRes->fields['format'];
        $catId = $entriesRes->fields['cat_id'];
        $insertSQL = "insert into blog_entries (blog_id, compat_entry_id, body, date, userid, title, karma, format, cat_id) values ($blogId, $compatEntryId, '$body', '$date', $userid, '$title', $karma, $format, $catId)";
        //print "INS: $insertSQL<br/>\n";
        $insertRes = $db->Execute($insertSQL);

	$idSQL = "select max(blog_entry_id) as id from blog_entries";
	$idRes = $db->Execute($idSQL);
	
        $sql = "update blog_comments set eid=".$idRes->fields['id']." where eid=$compatEntryId and bid=$blogId";
        $updateRes = $db->Execute($sql);

        $entriesRes->MoveNext();
    }
    $res->MoveNext();
}

// we really should not remove the old blog tables in this script. that should
// be a somewhat manual step, occuring after the user has verified the
// entries were copied over correctly.
// later this should print a link to a page that will delete the blog-specific tables.

?>

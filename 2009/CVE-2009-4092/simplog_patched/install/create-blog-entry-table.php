<?php
#include_once("lib.php");
// the $db connection is defined in upgrade2.php, in which we get included.
// grab the dictionary processor for this db connection.
#$dict = NewDataDictionary($db);

/* Next we need to defint the fields that will be added to the blog_entry table:
    blog_entry_id (number) autoincrement sequence, keyed
    // we also need to store the old entry ID from the blog_BLOGNAME table
    // in order to preserve the integrity of permalinks. we'll also have to
    // turn this into a dual key index.
    blog_id (number) not null
    compat_entry_id (number) not null
    body (text) not null, default ''
    date (timestamp) not null, default '0001-01-01 00:00:00'
    userid (number) not null
    title (varchar 64)
    karma (number) not null, default 0
    format (number) not null, default 0
    cat_id (number) not null, default 0
    */

$tableName = "blog_entries";

$fields = "
blog_entry_id I key notnull auto,
blog_id I notnull,
compat_entry_id I notnull,
body X notnull,
post_date T notnull,
date T notnull,
userid I notnull,
title C(128) notnull,
karma I default 0,
format I default 0,
cat_id I default 0
";

// define some basic table generation options
$opts = array('mysql' => 'ENGINE=MyISAM');

// generate the table SQL:
$blogEntryTableSQL = ($dict->CreateTableSQL($tableName, $fields, $opts));

// then define the indices
$indexName = "blog_id_entry_id_idx";
$indexOpts = array("UNIQUE");
$indexSQL = ($dict->CreateIndexSQL($indexName, $tableName, "blog_id,compat_entry_id", $indexOpts));
$dateIndex = "blog_entry_date_idx";
$dateSQL = ($dict->CreateIndexSQL($dateIndex, $tableName, "date", array()));
$titleIndex = "blog_entry_body_idx";
$titleSQL = ($dict->CreateIndexSQL($titleIndex, $tableName, "title", array()));

// and execute it.
//print_r($dict->MetaTables());
foreach($blogEntryTableSQL as $s) {
    $newTableSQL = "$newTableSQL\n$s;";
    $s = htmlspecialchars($s);
    if ($dbType == 'oci8') print "/\n";
}
foreach($indexSQL as $s) {
    $newIndexSQL = "$newIndexSQL\n$s;";
    $s = htmlspecialchars($s);
    if ($dbType == 'oci8') print "/\n";
}
foreach($dateSQL as $s) {
    $newDateSQL = "$newDateSQL\n$s;";
    $s = htmlspecialchars($s);
    if ($dbType == 'oci8') print "/\n";
}
foreach($titleSQL as $s) {
    $newTitleSQL = "$newTitleSQL\n$s;";
    $s = htmlspecialchars($s);
    if ($dbType == 'oci8') print "/\n";
}

if ( $db->Execute($newTableSQL) === false) {
    print "Error creating table $tableName<br/>\n";
}

if ($db->Execute($newIndexSQL) === false) {
    print "Error creating indices<br/>\n";
}

if ($db->Execute($newDateSQL) === false) {
    print "Error creating indices<br/>\n";
}

if ($db->Execute($newTitleSQL) === false) {
    print "Error creating indices<br/>\n";
}

// need to null out the array, because this file is included in another file that
// uses the $fields variable.
$fields = array();

?>

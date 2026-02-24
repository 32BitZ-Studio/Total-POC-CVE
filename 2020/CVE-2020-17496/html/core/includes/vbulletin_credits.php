<?php if (!defined('VB_ENTRY')) die('Access denied.');
/*========================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/

// display the credits table for use in admin/mod control panels

//not sure why this is a form -- we don't have any way to submit it
//however removing the form header destroys the formatting (which
//may be why) so we'll "fix" it and leave it.  Its not a problem
//for the modcp since the link doesn't go anywhere anyway.
print_form_header('admincp/index', 'home');
print_table_header($vbphrase['vbulletin_developers_and_contributors']);
print_column_style_code(array('white-space: nowrap', ''));

print_label_row('<b>' . 'Nulled by' . '</b>', '
	<a href="https://vbsupport.org/forum/" target="vbsupport">vBSupport.org</a>
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['project_management'] . '</b>', '
	Marjo Mercado,
	Thong Nguyen
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['development_lead'] . '</b>', '
	Kevin Sours
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['development'] . '</b>', '
	David Grove,
	Jin-Soo Jo,
	Nicolas Acerenza
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['product_management_user_experience_visual_design'] . '</b>', '
	Joe Rosenblum,
	Olga Mandrosov
	', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['qa'] . '</b>', '
	Allen H. Lin,
 	Jes&uacute;s Figueroa,
	Yves Rigaud
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['documentation'] . '</b>', '
	Wayne Luke
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['bussines_operations_management_and_customer_support'] . '</b>', '
	Aakif Nazir,
	Christian Rosch,
	Christine Tran,
	Joe Dibiasi,
	Joshua Gonzales,
	Mark Bowland,
	Trevor Hannant,
	Wayne Luke,
	Yves Rigaud
', '', 'top', NULL, false);

print_label_row('<b>' . $vbphrase['special_thanks_and_contributions'] . '</b>', '
	Abel Lawal,
	Alan Ordu&ntilde;o,
	Chen Xu,
	Danco Dimovski,
	Daniel Lee,
	Darren Gordon,
	Dominic Schlatter,
	Edwin Brown,
	Fabian Schonholz,
	Fernando Varesi,
	Francisco Aceves,
	Freddie Bingham,
	George Liu,
	Glenn Vergara,
	Gorgi Gichevski,
	Gregg Hartling,
	John McGanty
	Jorge Tiznado,
	Kyle Furlong,
	Lynne Sands,
	Mark Jean,
	Meghan Sensenbach,
	Michael Lavaveshkul,
	Miguel Montano,
	Neal Sainani,
	Paul Marsden,
	Pawel Grzesiecki,
	Rishi Basu,
	Sebastiano Vassellatti,
	Tadeo Valencia,
	Thao Pham,
	Tuan Nguyen,
	Xiaoyu Huang,
	Zachery Woods,
	Zafer Bahadir,
	Zoltan Szalay
', '', 'top', NULL, false);

print_table_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103774 $
|| #######################################################################
\*=========================================================================*/

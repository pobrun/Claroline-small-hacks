<?php
/**
 * CLAROLINE
 *
 * Simple access to users list and class.
 *
 * @version     $Revision: 1 $
 * @copyright   (c) Cabinet d'ingénierie PobRun
 * @license     http://www.gnu.org/copyleft/gpl.html (GPL) GENERAL PUBLIC LICENSE
 * @author      PobRun (Pierre-Olivier Bonnet <contact@pobrun.com>
 */

/*
Usage : change $rest_key
get users in json : http://xxxx/yyyy/rest.users.php?key=theawesomekey&action=getusers
get class in json : http://xxxx/yyyy/rest.users.php?key=theawesomekey&action=getclass
get users of a class in json : http://xxxx/yyyy/rest.users.php?key=theawesomekey&action=getusersfromclass&class=2
*/

$rest_key="theawesomekey";

if($_GET["key"]==$rest_key)
{
	require '../claroline/inc/claro_init_global.inc.php';
	require_once get_path('incRepositorySys') . '/lib/admin.lib.inc.php';
	require_once get_path('incRepositorySys') . '/lib/class.lib.php';
	require_once get_path('incRepositorySys') . '/lib/user.lib.php';


	$tbl_mdb_names = claro_sql_get_main_tbl();
	$tbl_user       = $tbl_mdb_names['user'];
	$tbl_class      = $tbl_mdb_names['user_category'];
	$tbl_class_user = $tbl_mdb_names['user_rel_profile_category'];

	switch($_GET["action"])
	{
	case "getusers":
		print(json_encode(getUsers($tbl_user)));
	break;
	case "getclass":
		print(json_encode(getClass($tbl_class)));
	break;
	case "getusersfromclass":
		print(json_encode(getUsersFromClass($tbl_user,$tbl_class_user,$_GET["class"])));
	break;
	
	}

	getClass($tbl_class);
}
else
{
	print("<p>Hey mate, you are in the wrong place.</p>");
}

function getClass($_tbl_class)
{
	$sql = "SELECT id,
		       class_parent_id,
		       name
		FROM `" . $_tbl_class . "`
		ORDER BY `name`";

	return claro_sql_query_fetch_all($sql);
}

function getUsers($_tbl_user)
{
	$sql = "SELECT distinct U.user_id      AS user_id,
		            U.nom          AS nom,
		            U.prenom       AS prenom,
		            U.nom          AS lastname,
		            U.prenom       AS firstname,
		            U.email        AS email,
		            U.officialCode AS officialCode,
			    U.isCourseCreator AS isCourseCreator,
		            U.username AS username,
		            U.password AS password
	    FROM `" . $_tbl_user . "` AS U";
	return claro_sql_query_fetch_all($sql);
}

function getUsersFromClass($_tbl_user,$_tbl_class_user,$_id_class)
{
	$classes_list = getSubClasses($_id_class);
	$classes_list[] = $_id_class;

	$sql = "SELECT distinct U.user_id      AS user_id,
		            U.nom          AS nom,
		            U.prenom       AS prenom,
		            U.nom          AS lastname,
		            U.prenom       AS firstname,
		            U.email        AS email,
		            U.officialCode AS officialCode,
			    U.isCourseCreator AS isCourseCreator,
		            U.username AS username,
		            U.password AS password
	    FROM `" . $_tbl_user . "` AS U
	    LEFT JOIN `" . $_tbl_class_user . "` AS CU
		ON U.`user_id`= CU.`user_id`
	    WHERE `CU`.`class_id`
		in (" . implode($classes_list,",") . ")";

	return claro_sql_query_fetch_all($sql);
}
?>

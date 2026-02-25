# CVE-2023-38891

## Authenticated SQL Injection Vulnerability in VTiger Open Source CRM v7.5

**Discovered by: Jacob Elliott**

**07/13/23**

## Summary

In the Reports module in VTiger CRM v7.5.0, there is insufficient checking of the selected fields for the report which are stored and then later reintroduced as a second-order SQL Injection when the report is run. This allows the attacker to leak arbitrary fields from the database including user password hashes, webservice API access keys, and other sensitive data.

## Proof Of Concept

After authenticating with the CRM, the user can browse to the Reports module and create a new report.

![image1](images/1.png)

Due to the way that the tables are joined, it seems to work best to choose a module that has records in it as the primary module. I chose Contacts, which contained one record. 

![image1](images/2.png)

Next, the user can select any legitimate fields from the primary module and continue the report creation process.

![image1](images/3.png)

Finally, the user can click the button to save the final report, while intercepting connections with a proxy tool like BurpSuite. In the selected_fields parameter, the previously selected fields are passed to the save function in the format:

```sql_table:sql_column:label:field_name```

At this point, the user can modify the sql_table and sql_column to any arbitrary values they would like to leak from the database. For this POC, I used:

```vtiger_users:user_name:Contacts_Salutation:salutationtype```

and

```vtiger_users:user_password:Contacts_First_Name:firstname```

After forwarding the modified request, we are presented with the final report which contains the desired columns from the database, revealing the username and password hash of the admin user.

![image1](images/4.png)

The lack of proper checking is introduced in modules/Reports/ReportRun.php (lines 394-398). Each of the provided column names are split on “:”.

```php
$selectedfields = explode(":", $fieldcolname);
```

And then if the user is not an admin, then the script checks to see if the field is in an array of permitted fields which is generated from the selected primary module for the report:

```php
!in_array($selectedfields[3], $permitted_fields[$module])
```

However, recall the input that was given:

```vtiger_users:user_name:Contacts_Salutation:salutationtype```

Because the “permitted fields” are being checked against the element at index 3 in the array, the field that is being checked is salutationtype in the Contacts module, which is not considered sensitive and so it is permitted for export. However, the table and column provided in the first two elements in the array undergo no such verification, leading to the data exposure.

## Remediation

This issue was fixed in [this commit](https://code.vtiger.com/vtiger/vtigercrm/-/commit/f41446eb34661ff69a64bd818d6b0e88f26b50f0) by changing the validation on selected fields so that they are checked against allowed fields hard-coded in each module.

```php

public function checkPermission(Vtiger_Request $request) {
		parent::checkPermission($request);

		$record = $request->get('record');
		if ($record) {
			$reportModel = Reports_Record_Model::getCleanInstance($record);
			if (!$reportModel->isEditable()) {
				throw new AppException(vtranslate('LBL_PERMISSION_DENIED'));
			}
		}

             	$selectedFields = $request->get('selected_fields');
		$groupbyfields = $request->get('groupbyfield');
		$fieldsData = array($selectedFields, $groupbyfields);

		foreach ($fieldsData as $selectedField){
			foreach ($selectedField as $field) {
				list($tablename, $colname, $module_field, $fieldname, $single) = split(":", $field);
				list($module, $fieldName) = split("_", $module_field, 2);
				$moduleModel = Vtiger_Module_Model::getInstance($module);
				$fieldModel = Vtiger_Field_Model::getInstance($fieldname, $moduleModel);

				if (($fieldModel->table !== $tablename) || ($fieldModel->column !== $colname)) {
					throw new AppException(vtranslate('LBL_PERMISSION_DENIED'));
				}
			}
		}  
		return true;
	}
```
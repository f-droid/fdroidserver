<?php
// Path to the AndroidManifest.xml-file from the Android source. Get it from https://raw.github.com/android/platform_frameworks_base/master/core/res/AndroidManifest.xml for example.
$android_manifest_file_path = 'AndroidManifest.xml';
// Path to the strings.xml-file from the Android source. Get it from https://raw.github.com/android/platform_frameworks_base/master/core/res/res/values/strings.xml for example.
$android_strings_file_path = 'strings.xml';

$cache_file_path = 'android-permissions.cache';

// Returns an associative array with android permissions and data about them
function get_android_permissions_array($android_manifest_file_path, $android_strings_file_path, $cache_file_path) {

	// Check status of cache
	$android_manifest_file_stat = stat($android_manifest_file_path);
	$android_manifest_file_mtime = $android_manifest_file_stat['mtime'];
	$android_strings_file_stat = stat($android_strings_file_path);
	$android_strings_file_mtime = $android_strings_file_stat['mtime'];
	$cache_file_mtime = 0;
	if(file_exists($cache_file_path)) {
		$cache_file_stat = stat($cache_file_path);
		$cache_file_mtime = $cache_file_stat['mtime'];
	}
	
	// If the cache is fresh, use it instead
	if($android_manifest_file_mtime < $cache_file_mtime && $android_strings_file_mtime < $cache_file_mtime ) {
		$cache_file_handle = fopen($cache_file_path, 'r');
		$cache_file_content = fread($cache_file_handle, filesize($cache_file_path));
		fclose($cache_file_handle);
		
		$permissions = unserialize($cache_file_content);
		
		return $permissions;
	}

	// We are updating the cache, touch the file (note: race condition possible between stating the cache file above and this line...)
	touch($cache_file_path);
	
	// Get permission raw data from XML
	$manifestDoc = new DOMDocument;
	$manifestDoc->load($android_manifest_file_path);
	$manifestXpath = new DOMXPath($manifestDoc);

	$stringsDoc = new DOMDocument;
	$stringsDoc->load($android_strings_file_path);
	$stringsXpath = new DOMXPath($stringsDoc);
	
	$comment = '';
	foreach ($manifestXpath->query('node()') as $node) {
		// Save permissions and permission groups from tags
		if($node->nodeName == 'permission-group' || $node->nodeName == 'permission') {
			$name = $node->attributes->getNamedItem('name')->value;
			$name = substr(strrchr($name,'.'), 1);

			// Lookup the human readable title
			$labelObject = $node->attributes->getNamedItem('label');
			$labelString = $name;
			if( $labelObject !== NULL ) {
				$labelName = substr(strrchr($labelObject->value,'/'),1);
				$labelStringObject = $stringsXpath->query('//string[@name="'.$labelName.'"]');
				$labelString = ucfirst($labelStringObject->item(0)->nodeValue);
			}

			// Lookup the human readable description
			$descriptionObject = $node->attributes->getNamedItem('description');
			$descriptionString = '(Description missing)';
			if($descriptionObject !== NULL) {
				$descriptionName = substr(strrchr($descriptionObject->value,'/'),1);
				$descriptionStringObject = $stringsXpath->query('//string[@name="'.$descriptionName.'"]');
				$descriptionString = ucfirst($descriptionStringObject->item(0)->nodeValue);
			}
			
			$permissions[$node->nodeName][$name]['label'] = $labelString;
			$permissions[$node->nodeName][$name]['description'] = $descriptionString;
			$permissions[$node->nodeName][$name]['comment'] = str_replace(array("\r\n", "\r", "\n", "\t", '  '), '', $comment);
			
			if($node->nodeName == 'permission') {
				$permissionGroupObject = $node->attributes->getNamedItem('permissionGroup');
				$permissionGroup = 'none';
				if($permissionGroupObject !== NULL) {
					$permissionGroup = substr(strrchr($permissionGroupObject->value,'.'), 1);
				}
				
				$permissions[$node->nodeName][$name]['permissionGroup'] = $permissionGroup;
				$permissions[$node->nodeName][$name]['protectionLevel'] = $node->attributes->getNamedItem('protectionLevel')->value;
			}
		}

		// Cache descriptions from comments preceding the tags
		if($node->nodeName == '#comment') {
			$comment .= $node->textContent;
		}
		elseif($node->nodeName != '#text') {
			$comment = '';
		}
	}

	// Update cache with serialized permissions
	$cache_file_handle = fopen($cache_file_path, 'w');
	fwrite($cache_file_handle, serialize($permissions));
	fclose($cache_file_handle);
	
	return $permissions;
}
?>
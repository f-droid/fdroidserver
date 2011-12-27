<?php
// Path to the AndroidManifest.xml-file from the Android source. Get it from https://raw.github.com/android/platform_frameworks_base/master/core/res/AndroidManifest.xml for example.
$android_manifest_file_path = 'AndroidManifest.xml';

// Returns an associative array with android permissions and data about them
function get_android_permissions_array($android_manifest_file_path) {

	$doc = new DOMDocument;
	$doc->load($android_manifest_file_path);

	$xpath = new DOMXPath($doc);

	$description = '';
	
	foreach ($xpath->query('node()') as $node) {
		// Save permissions and permission groups from tags
		if($node->nodeName == 'permission-group' || $node->nodeName == 'permission') {
			$name = $node->attributes->getNamedItem('name')->value;
			$name = substr(strrchr($name,'.'), 1);
			$permissions[$node->nodeName][$name]['description'] = str_replace(array("\r\n", "\r", "\n", "\t", '  '), '', $description);
			
			if($node->nodeName == 'permission') {
				$permissions[$node->nodeName][$name]['permissionGroup'] = substr(strrchr($node->attributes->getNamedItem('permissionGroup')->value,'.'), 1);
				$permissions[$node->nodeName][$name]['protectionLevel'] = $node->attributes->getNamedItem('protectionLevel')->value;
			}
		}

		// Cache descriptions from comments preceding the tags
		if($node->nodeName == '#comment') {
			$description .= $node->textContent;
		}
		elseif($node->nodeName != '#text') {
			$description = '';
		}
	}
	
	return $permissions;
}
?>
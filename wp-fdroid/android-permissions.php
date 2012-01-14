<?php
// Class that provides PHP-friendly android permissions information from the raw Andoid source XML files that describes the permissions.
class AndroidPermissions
{

	// Path to the AndroidManifest.xml-file from the Android source. Get it from https://raw.github.com/android/platform_frameworks_base/master/core/res/AndroidManifest.xml for example.
	private $android_manifest_file_path;
	// Path to the strings.xml-file from the Android source. Get it from https://raw.github.com/android/platform_frameworks_base/master/core/res/res/values/strings.xml for example.
	private $android_strings_file_path;
	// Path to the file where the resulting permissions data will be cached. NOTE: Must be writable by PHP!
	private $cache_file_path;

	public function __construct($android_manifest_file_path_in = 'AndroidManifest.xml', $android_strings_file_path_in = 'strings.xml', $cache_file_path_in = 'android-permissions.cache') {
		$this->android_manifest_file_path = $android_manifest_file_path_in;
		$this->android_strings_file_path = $android_strings_file_path_in;
		$this->cache_file_path = $cache_file_path_in;
	}
	
	// Returns an associative array with android permissions and data about them
	function get_permissions_array() {

		// Check status of cache
		$android_manifest_file_stat = stat($this->android_manifest_file_path);
		$android_manifest_file_mtime = $android_manifest_file_stat['mtime'];
		$android_strings_file_stat = stat($this->android_strings_file_path);
		$android_strings_file_mtime = $android_strings_file_stat['mtime'];
		$cache_file_mtime = 0;
		if(file_exists($this->cache_file_path)) {
			$cache_file_stat = stat($this->cache_file_path);
			$cache_file_mtime = $cache_file_stat['mtime'];
		}

		// If the cache is fresh, use it instead
		if($android_manifest_file_mtime < $cache_file_mtime && $android_strings_file_mtime < $cache_file_mtime ) {
			$cache_file_handle = fopen($this->cache_file_path, 'r');
			$cache_file_content = fread($cache_file_handle, filesize($this->cache_file_path));
			fclose($cache_file_handle);

			$permissions = unserialize($cache_file_content);

			return $permissions;
		}

		// We are updating the cache, touch the file (note: race condition possible between stating the cache file above and this line...)
		touch($this->cache_file_path);

		// Get permission raw data from XML
		$manifestDoc = new DOMDocument;
		$manifestDoc->load($this->android_manifest_file_path);
		$manifestXpath = new DOMXPath($manifestDoc);

		$stringsDoc = new DOMDocument;
		$stringsDoc->load($this->android_strings_file_path);
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

				$permissions[$node->nodeName][$name]['label'] = stripslashes($labelString);
				$permissions[$node->nodeName][$name]['description'] = stripslashes($descriptionString);
				$permissions[$node->nodeName][$name]['comment'] = stripslashes(str_replace(array("\r\n", "\r", "\n", "\t", '  '), '', $comment));

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
		$cache_file_handle = fopen($this->cache_file_path, 'w');
		fwrite($cache_file_handle, serialize($permissions));
		fclose($cache_file_handle);

		return $permissions;
	}
}
?>

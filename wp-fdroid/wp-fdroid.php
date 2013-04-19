<?php
/*
Plugin Name: WP FDroid
Plugin URI: http://f-droid.org/repository
Description: An FDroid repository browser
Author: Ciaran Gultnieks
Version: 0.01
Author URI: http://ciarang.com

Revision history
0.01 - 2010-12-04: Initial development version

*/

include('android-permissions.php');

class FDroid
{

	// Our text domain, for internationalisation
	private $textdom='wp-fdroid';

	private $site_path;

	// Constructor
	function FDroid() {
		// Add filters etc here!
		add_shortcode('fdroidrepo',array($this, 'do_shortcode'));
		add_filter('query_vars',array($this, 'queryvars'));
		$this->inited=false;
                $this->site_path=getenv('DOCUMENT_ROOT');
                wp_register_sidebar_widget('fdroid_latest', 'FDroid Latest', 'widget_fdroidlatest');
	}


	// Register additional query variables. (Handler for the 'query_vars' filter)
	function queryvars($qvars) {
		$qvars[]='fdfilter';
		$qvars[]='fdcategory';
		$qvars[]='fdid';
		$qvars[]='fdpage';
		$qvars[]='fdstyle';
		return $qvars;
	}


	// Lazy initialise. All non-trivial members should call this before doing anything else.
	function lazyinit() {
		if(!$this->inited) {
			load_plugin_textdomain($this->textdom, PLUGINDIR.'/'.dirname(plugin_basename(__FILE__)), dirname(plugin_basename(__FILE__)));

			$this->inited=true;
		}
	}

	// Gets a required query parameter by name.
	function getrequiredparam($name) {
		global $wp_query;
		if(!isset($wp_query->query_vars[$name]))
			wp_die("Missing parameter ".$name,"Error");
		return $wp_query->query_vars[$name];
	}

	// Handler for the 'fdroidrepo' shortcode.
	//  $attribs - shortcode attributes
	//  $content - optional content enclosed between the starting and
	//			 ending shortcode
	// Returns the generated content.
	function do_shortcode($attribs,$content=null) {
		global $wp_query,$wp_rewrite;
		$this->lazyinit();

		// Init local query vars
		foreach($this->queryvars(array()) as $qv) {
			if(array_key_exists($qv,$wp_query->query_vars)) {
				$query_vars[$qv] = $wp_query->query_vars[$qv];
			} else {
				$query_vars[$qv] = null;
			}
		}

		// Santiy check query vars
		if(!isset($query_vars['fdpage']) || !is_numeric($query_vars['fdpage']) || $query_vars['fdpage'] <= 0) {
			$query_vars['fdpage'] = 1;
		}

		$out = '';

		if(isset($attribs['search']) && $query_vars['fdfilter']===null) {
			$query_vars['fdfilter'] = '';
		}

		if($query_vars['fdcategory'] == 'All categories') {
			unset($query_vars['fdcategory']);
		}
		
		if($query_vars['fdid']!==null) {
			$out.=$this->get_app($query_vars);
		} else {
			if($query_vars['fdfilter'] !== null) {
				$out.='<form name="searchform" action="" method="get">';
				$out.='<p><input name="fdfilter" type="text" value="'.sanitize_text_field($query_vars['fdfilter']).'" size="30"> ';
				$out.='<input type="submit" value="Search"></p>';
				$out.=$this->makeformdata($query_vars);
				$out.='</form>'."\n";
			}

			$out.=$this->get_apps($query_vars);
		}

		return $out;
	}


	// Get a URL for a full description of a license, as given by one of our
	// pre-defined license abbreviations. This is a temporary function, as this
	// needs to be data-driven so the same information can be used by the client,
	// the web site and the documentation.
	function getlicenseurl($license) {
	    switch($license) {
        	    case 'MIT':
			return 'http://www.gnu.org/licenses/license-list.html#X11License';
		    case 'NewBSD':
			return 'http://www.gnu.org/licenses/license-list.html#ModifiedBSD';
		    case 'BSD':
			return 'http://www.gnu.org/licenses/license-list.html#OriginalBSD';
		    case 'GPLv3':
		    case 'GPLv3+':
			return 'http://www.gnu.org/licenses/license-list.html#GNUGPL';
		    case 'GPLv2':
		    case 'GPLv2+':
			return 'http://www.gnu.org/licenses/license-list.html#GPLv2';
		    case 'LGPL':
			return 'http://www.gnu.org/licenses/license-list.html#LGPL';
		    case 'Apache2':
			return 'http://www.gnu.org/licenses/license-list.html#apache2';
		    default:
			return null;
	    }
	}

	function get_app($query_vars) {
		global $permissions_data;
		$permissions_object = new AndroidPermissions($this->site_path.'/wp-content/plugins/wp-fdroid/AndroidManifest.xml',
			$this->site_path.'/wp-content/plugins/wp-fdroid/strings.xml',
			sys_get_temp_dir().'/android-permissions.cache');
		$permissions_data = $permissions_object->get_permissions_array();

		// Get app data
		$xml = simplexml_load_file($this->site_path.'/repo/index.xml');
		foreach($xml->children() as $app) {

			$attrs=$app->attributes();
			if($attrs['id']==$query_vars['fdid']) {
				$apks=array();;
				foreach($app->children() as $el) {
					switch($el->getName()) {
						case "name":
							$name=$el;
							break;
						case "icon":
							$icon=$el;
							break;
						case "summary":
							$summary=$el;
							break;
						case "desc":
							$desc=$el;
							break;
						case "license":
							$license=$el;
							break;
						case "source":
							$source=$el;
							break;
						case "tracker":
							$issues=$el;
							break;
						case "donate":
							$donate=$el;
							break;
						case "web":
							$web=$el;
							break;
						case "antifeatures";
							$antifeatures=$el;
							break;
						case "requirements";
							$requirements=$el;
							break;
						case "package":
							$thisapk=array();
							foreach($el->children() as $pel) {
								switch($pel->getName()) {
								case "version":
									$thisapk['version']=$pel;
									break;
								case "vercode":
									$thisapk['vercode']=$pel;
									break;
								case "apkname":
									$thisapk['apkname']=$pel;
									break;
								case "srcname":
									$thisapk['srcname']=$pel;
									break;
								case "hash":
									$thisapk['hash']=$pel;
									break;
								case "size":
									$thisapk['size']=$pel;
									break;
								case "sdkver":
									$thisapk['sdkver']=$pel;
									break;
								case "permissions":
									$thisapk['permissions']=$pel;
									break;
								}
							}
							$apks[]=$thisapk;

					}
				}

				// Generate app diff data
				foreach(array_reverse($apks, true) as $key=>$apk) {
					if(isset($previous)) {
						// Apk size
						$apks[$key]['diff']['size'] = $apk['size']-$previous['size'];
					}

					// Permissions
					$permissions = explode(',',$apk['permissions']);
					$permissionsPrevious = isset($previous['permissions'])?explode(',',$previous['permissions']):array();
					$apks[$key]['diff']['permissions']['added'] = array_diff($permissions, $permissionsPrevious);
					$apks[$key]['diff']['permissions']['removed'] = array_diff($permissionsPrevious, $permissions);

					$previous = $apk;
				}

				// Output app information
				$out='<div id="appheader">';
				$out.='<div style="float:left;padding-right:10px;"><img src="' . site_url() . '/repo/icons/'.$icon.'" width=48></div>';
				$out.='<p><span style="font-size:20px">'.$name."</span>";
				$out.="<br>".$summary."</p>";
				$out.="</div>";

				$out.=str_replace('href="fdroid.app:', 'href="/repository/browse/?fdid=', $desc);

				if(isset($antifeatures)) {
					$antifeaturesArray = explode(',',$antifeatures);
					foreach($antifeaturesArray as $antifeature) {
						$antifeatureDesctiption = $this->get_antifeature_description($antifeature);
						$out.='<p style="border:3px solid #CC0000;background-color:#FFDDDD;padding:5px;"><strong>'.$antifeatureDesctiption['name'].'</strong><br />';
						$out.=$antifeatureDesctiption['description'].'</p>';
					}
				}

				$out.="<p>";
				$licenseurl=$this->getlicenseurl($license);
				$out.="<b>License:</b> ";
				if($licenseurl)
				    $out.='<a href="'.$licenseurl.'" target="_blank">';
				$out.=$license;
				if($licenseurl)
				    $out.='</a>';

				if(isset($requirements)) {
					$out.='<br /><b>Additional requirements:</b> '.$requirements;
				}
				$out.="</p>";

				$out.="<p>";
				if(strlen($web)>0)
					$out.='<b>Website:</b> <a href="'.$web.'">'.$web.'</a><br />';
				if(strlen($issues)>0)
					$out.='<b>Issue Tracker:</b> <a href="'.$issues.'">'.$issues.'</a><br />';
				if(strlen($source)>0)
					$out.='<b>Source Code:</b> <a href="'.$source.'">'.$source.'</a><br />';
				if($donate && strlen($donate)>0)
					$out.='<b>Donate:</b> <a href="'.$donate.'">'.$donate.'</a><br />';
				$out.="</p>";

				$out.='<script type="text/javascript">';
				$out.='function showHidePermissions(id) {';
				$out.='  if(document.getElementById(id).style.display==\'none\')';
				$out.='	document.getElementById(id).style.display=\'block\';';
				$out.='  else';
				$out.='	document.getElementById(id).style.display=\'none\';';
				$out.='  return false;';
				$out.='}';
				$out.='</script>';

				$out.="<h3>Packages</h3>";

				$out.="<p><b>NOTE:</b> Although APK downloads are available below to give ";
				$out.="you the choice, you should be aware that by installing that way you ";
				$out.="will not receive update notifications, and it's a less secure way ";
				$out.="to download, especially if you are not currently using HTTPS. ";
				$out.="We recommend that you install the F-Droid client and use that.</p>";

				$i=0;
				foreach($apks as $apk) {
					$first = $i+1==count($apks);
                                        $out.="<p><b>Version ".$apk['version']."</b><br />";

                                        // Is this source or binary?
                                        $srcbuild = isset($apk['srcname']) && file_exists($this->site_path.'/repo/'.$apk['srcname']);

                                        $out.="<p>This version is built and signed by ";
                                        if($srcbuild) {
                                            $out.="F-Droid, and guaranteed to correspond to the source tarball below.</p>";
                                        } else {
                                            $out.="the original developer.</p>";
                                        }
					$out.='<a href="https://f-droid.org/repo/'.$apk['apkname'].'">download apk</a> ';
					$out.=$this->human_readable_size($apk['size']);
					$diffSize = $apk['diff']['size'];
					if(abs($diffSize) > 500) {
						$out.=' <span style="color:#AAAAAA;">(';
						$out.=$diffSize>0?'+':'';
						$out.=$this->human_readable_size($diffSize, 1).')</span>';
					}
					if($srcbuild) {
						$out.='<br /><a href="https://f-droid.org/repo/'.$apk['srcname'].'">source tarball</a> ';
						$out.=$this->human_readable_size(filesize($this->site_path.'/repo/'.$apk['srcname']));
					}

					if(isset($apk['permissions'])) {
						// Permissions diff link
						if($first == false) {
							$permissionsAddedCount = count($apk['diff']['permissions']['added']);
							$permissionsRemovedCount = count($apk['diff']['permissions']['removed']);
							$divIdDiff='permissionsDiff'.$i;
							if($permissionsAddedCount || $permissionsRemovedCount) {
								$out.='<br /><a href="javascript:void(0);" onClick="showHidePermissions(\''.$divIdDiff.'\');">permissions diff</a>';
								$out.=' <span style="color:#AAAAAA;">(';
								if($permissionsAddedCount)
									$out.='+'.$permissionsAddedCount;
								if($permissionsAddedCount && $permissionsRemovedCount)
									$out.='/';
								if($permissionsRemovedCount)
									$out.='-'.$permissionsRemovedCount;
								$out.=')</span>';
							}
							else
							{
								$out.='<br /><span style="color:#999999;">no permission changes</span>';
							}
						}

						// Permissions list link
						$permissionsListString = $this->get_permission_list_string(explode(',',$apk['permissions']), $permissions_data, $summary);
						/*if($i==0)
							$divStyleDisplay='block';
						else*/
							$divStyleDisplay='none';
						$divId='permissions'.$i;
						$out.='<br /><a href="javascript:void(0);" onClick="showHidePermissions(\''.$divId.'\');">view permissions</a>';
						$out.=' <span style="color:#AAAAAA;">['.$summary.']</span>';
						$out.='<br/>';

						// Permissions list
						$out.='<div style="display:'.$divStyleDisplay.';" id="'.$divId.'">';
						$out.=$permissionsListString;
						$out.='</div>';

						// Permissions diff
						{
							$out.='<div style="display:'.$divStyleDisplay.';" id="'.$divIdDiff.'">';
							$permissionsRemoved = $apk['diff']['permissions']['removed'];
							usort($permissionsRemoved, "permissions_cmp");

							// Added permissions
							if($permissionsAddedCount) {
								$out.='<h5>ADDED</h5><br />';
								$out.=$this->get_permission_list_string($apk['diff']['permissions']['added'], $permissions_data, $summary);
							}

							// Removed permissions
							if($permissionsRemovedCount) {
								$out.='<h5>REMOVED</h5><br />';
								$out.=$this->get_permission_list_string($apk['diff']['permissions']['removed'], $permissions_data, $summary);
							}

							$out.='</div>';
						}
					}
					else {
						$out.='<br /><span style="color:#999999;">no extra permissions needed</span><br />';
					}

					$out.='</p>';
					$i++;
				}

				$out.='<hr><p><a href="'.makelink($query_vars,array('fdid'=>null)).'">Index</a></p>';

				return $out;
			}
		}
		return "<p>Application not found</p>";
	}

	private function get_permission_list_string($permissions, $permissions_data, &$summary) {
		$out='';
		usort($permissions, "permissions_cmp");
		$permission_group_last = '';
		foreach($permissions as $permission) {
			$permission_group = $permissions_data['permission'][$permission]['permissionGroup'];
			if($permission_group != $permission_group_last) {
				$permission_group_label = $permissions_data['permission-group'][$permission_group]['label'];
				if($permission_group_label=='') $permission_group_label = 'Extra/Custom';
				$out.='<strong>'.strtoupper($permission_group_label).'</strong><br/>';
				$permission_group_last = $permission_group;
			}

			$out.=$this->get_permission_protection_level_icon($permissions_data['permission'][$permission]['protectionLevel']).' ';
			$out.='<strong>'.$permissions_data['permission'][$permission]['label'].'</strong> [<code>'.$permission.'</code>]<br/>';
			if($permissions_data['permission'][$permission]['description']) $out.=$permissions_data['permission'][$permission]['description'].'<br/>';
			//$out.=$permissions_data['permission'][$permission]['comment'].'<br/>';
			$out.='<br/>';

			if(!isset($summaryCount[$permissions_data['permission'][$permission]['protectionLevel']]))
				$summaryCount[$permissions_data['permission'][$permission]['protectionLevel']] = 0;
			$summaryCount[$permissions_data['permission'][$permission]['protectionLevel']]++;
		}

                $summary = '';
                if(isset($summaryCount)) {
		        foreach($summaryCount as $protectionLevel => $count) {
			        $summary .= $this->get_permission_protection_level_icon($protectionLevel, 'regular').' '.$count;
			        $summary .= ', ';
                        }
                }
		$summary = substr($summary,0,-2);

		return $out;
	}

	private function get_permission_protection_level_icon($protection_level, $size='adjusted') {
		$iconString = '';
		if($protection_level=='dangerous') {
			$iconString .= '<span style="color:#DD9900;';
			if($size=='adjusted')
				$iconString .= 'font-size:150%;';
			$iconString .= '">&#x26a0;</span>';	// WARNING SIGN
		}
		elseif($protection_level=='normal') {
			$iconString .= '<span style="color:#6666FF;';
			if($size=='adjusted')
				$iconString .= 'font-size:110%;';
			$iconString .= '">&#x24D8;</span>';	// CIRCLED LATIN SMALL LETTER I
		}
		elseif($protection_level=='signature') {
			$iconString .= '<span style="color:#33AAAA;';
			if($size=='adjusted')
				$iconString .= 'font-size:140%;';
			$iconString .= '">&#x273D;</span>';	// HEAVY TEARDROP-SPOKED ASTERISK
		}
		elseif($protection_level=='signatureOrSystem') {
			$iconString .= '<span style="color:#DD66DD;';
			if($size=='adjusted')
				$iconString .= 'font-size:140%;';
			$iconString .= '">&#x269B;</span>';	// ATOM SYMBOL
		}
		else {
			$iconString .= '<span style="color:#33AA33';
			if($size=='adjusted')
				$iconString .= ';font-size:130%;';
			$iconString .= '">&#x2699;</span>';	// GEAR
		}

		return $iconString;
	}

	private function human_readable_size($size, $minDiv=0) {
		$si_prefix = array('bytes','kB','MB');
		$div = 1024;

		for($i=0;(abs($size) > $div && $i < count($si_prefix)) || $i<$minDiv;$i++) {
			$size /= $div;
		}

		return round($size,max(0,$i-1)).' '.$si_prefix[$i];
	}

	private function get_antifeature_description($antifeature) {
		// Anti feature names and descriptions
		$antifeatureDesctiption['ads']['name'] = 'Advertising';
		$antifeatureDesctiption['ads']['description'] = 'This application contains advertising';
		$antifeatureDesctiption['tracking']['name'] = 'Tracks You';
		$antifeatureDesctiption['tracking']['description'] = 'This application tracks and reports your activity to somewhere';
		$antifeatureDesctiption['nonfreenet']['name'] = 'Non-Free Network Services';
		$antifeatureDesctiption['nonfreenet']['description'] = 'This application promotes a non-Free network service';
		$antifeatureDesctiption['nonfreeadd']['name'] = 'Non-Free Addons';
		$antifeatureDesctiption['nonfreeadd']['description'] = 'This application promotes non-Free add-ons';
		$antifeatureDesctiption['nonfreedep']['name'] = 'Non-Free Dependencies';
		$antifeatureDesctiption['nonfreedep']['description'] = 'This application depends on another non-Free application';

		$antifeatureLower = strtolower($antifeature);
		if(isset($antifeatureDesctiption[$antifeatureLower])) {
			return $antifeatureDesctiption[$antifeatureLower];
		}
		return array('name'=>$antifeature);
	}


	function get_apps($query_vars) {

		$xml = simplexml_load_file($this->site_path."/repo/index.xml");
		$matches = $this->show_apps($xml,$query_vars,$numpages);

		$out='';

		if(($query_vars['fdfilter']===null || $query_vars['fdfilter']!='') && $numpages>0)
		{
			$out.='<div style="float:left;">';
                        if($query_vars['fdfilter']===null) {

				$categories = array('All categories');
				$handle = fopen(getenv('DOCUMENT_ROOT').'/repo/categories.txt', 'r');
				if ($handle) {
					while (($buffer = fgets($handle, 4096)) !== false) {
					    $categories[] = rtrim($buffer);
					}
				    fclose($handle);
				}

				$out.='<form name="categoryform" action="" method="get">';
				$out.=$this->makeformdata($query_vars);
				
				$out.='<select name="fdcategory" style="color:#333333;" onChange="document.categoryform.submit();">';
				foreach($categories as $category) {
					$out.='<option';
					if(isset($query_vars['fdcategory']) && $category==$query_vars['fdcategory'])
						$out.=' selected';
					$out.='>'.$category.'</option>';
				}
				$out.='</select>';
				
				$out.='</form>'."\n";
			}
			else {
				$out.='Applications matching "'.sanitize_text_field($query_vars['fdfilter']).'"';
			}
			$out.="</div>";

			$out.='<div style="float:right;">';
			$out.='<a href="'.makelink($query_vars, array('fdstyle'=>'list')).'">List</a> | ';
			$out.='<a href="'.makelink($query_vars, array('fdstyle'=>'grid')).'">Grid</a>';
			$out.='</div>';

			$out.='<br break="all"/>';
		}

		if($numpages>0) {
			$out.=$matches;

			$out.='<hr><p>';

			$out.='<div style="width:20%; float:left; text-align:left;">';
			$out.=' Page '.$query_vars['fdpage'].' of '.$numpages.' ';
			$out.='</div>';

			$out.='<div style="width:60%; float:left; text-align:center;">';
			if($numpages>1) {
				for($i=1;$i<=$numpages;$i++) {
					if($i == $query_vars['fdpage']) {
						$out.='<b>'.$i.'</b>';
					} else {
						$out.='<a href="'.makelink($query_vars, array('fdpage'=>$i)).'">';
						$out.=$i;
						$out.='</a>';
					}
					$out.=' ';
				}
				$out.=' ';
			}
			$out.='</div>';

			$out.='<div style="width:20%; float:left; text-align:right;">';
			if($query_vars['fdpage']!=$numpages) {
				$out.='<a href="'.makelink($query_vars, array('fdpage'=>($query_vars['fdpage']+1))).'">next&gt;</a> ';
			}
			$out.='</div>';

			$out.='</p>';
		} else if($query_vars['fdfilter']!='') {
			$out.='<p>No matches</p>';
		}

		return $out;
	}


	function makeformdata($query_vars) {

		$out='';

		$out.='<input type="hidden" name="page_id" value="'.(int)get_query_var('page_id').'">';
		foreach($query_vars as $name => $value) {
			if($value !== null && $name != 'fdfilter' && !($name == 'fdpage' && (int)$value ==1))
				$out.='<input type="hidden" name="'.$name.'" value="'.sanitize_text_field($value).'">';
		}

		return $out;
	}


	function show_apps($xml,$query_vars,&$numpages) {

		$skipped=0;
		$got=0;
		$total=0;

		if($query_vars['fdstyle']=='grid') {
			$outputter = new FDOutGrid();
		} else {
			$outputter = new FDOutList();
		}

		$out = "";

		$out.=$outputter->outputStart();

		foreach($xml->children() as $app) {

			if($app->getName() == 'repo') continue;
			$appinfo['attrs']=$app->attributes();
			$appinfo['id']=$appinfo['attrs']['id'];
			foreach($app->children() as $el) {
				switch($el->getName()) {
					case "name":
						$appinfo['name']=$el;
						break;
					case "icon":
						$appinfo['icon']=$el;
						break;
					case "summary":
						$appinfo['summary']=$el;
						break;
					case "desc":
						$appinfo['description']=$el;
						break;
					case "license":
						$appinfo['license']=$el;
						break;
					case "category":
						$appinfo['category']=$el;
						break;
				}
			}

			if(($query_vars['fdfilter']===null || $query_vars['fdfilter']!='' && (stristr($appinfo['name'],$query_vars['fdfilter']) || stristr($appinfo['summary'],$query_vars['fdfilter']) || stristr($appinfo['description'],$query_vars['fdfilter']))) && (!isset($query_vars['fdcategory']) || $query_vars['fdcategory'] && $query_vars['fdcategory']==$appinfo['category'])) {
				if($skipped<($query_vars['fdpage']-1)*$outputter->perpage) {
					$skipped++;
				} else if($got<$outputter->perpage) {
					$out.=$outputter->outputEntry($query_vars, $appinfo);
					$got++;
				}
				$total++;
			}

		}

		$out.=$outputter->outputEnd();

		$numpages = ceil((float)$total/$outputter->perpage);

		return $out;
	}
}

// Class to output app entries in a detailed list format
class FDOutList
{
	var $perpage=30;

	function FDOutList() {
	}

	function outputStart() {
		return '';
	}

	function outputEntry($query_vars, $appinfo) {
		$out="";
		$out.='<hr style="clear:both;" />'."\n";
		$out.='<a href="'.makelink($query_vars, array('fdid'=>$appinfo['id'])).'">';
		$out.='<div id="appheader">';

                $out.='<div style="float:left;padding-right:10px;"><img src="' . site_url() . '/repo/icons/'.$appinfo['icon'].'" style="width:48px;border:none;"></div>';

		$out.='<div style="float:right;">';
		$out.='<p>Details...</p>';
		$out.="</div>\n";

		$out.='<p style="color:#000000;"><span style="font-size:20px;">'.$appinfo['name']."</span>";
		$out.="<br>".$appinfo['summary']."</p>\n";

		$out.="</div>\n";
		$out.='</a>';

		return $out;
	}

	function outputEnd() {
		return '';
	}
}

// Class to output app entries in a compact grid format
class FDOutGrid
{
	var $perpage=80;

	var $itemCount = 0;

	function FDOutGrid() {
	}

	function outputStart() {
		return "\n".'<table border="0" width="100%"><tr>'."\n";
	}

	function outputEntry($query_vars, $appinfo) {
		$link=makelink($query_vars, array('fdid'=>$appinfo['id']));

		$out='';

		if($this->itemCount%4 == 0 && $this->itemCount > 0)
		{
			$out.='</tr><tr>'."\n";
		}

		$out.='<td align="center" valign="top" style="background-color:#F8F8F8;">';
		$out.='<p>';
		$out.='<div id="appheader" style="text-align:center;width:110px;">';

		$out.='<a href="'.$link.'" style="border-bottom-style:none;">';
		$out.='<img src="' . site_url() . '/repo/icons/'.$appinfo['icon'].'" style="width:48px;border-width:0;padding-top:5px;padding-bottom:5px;"><br/>';
		$out.=$appinfo['name'].'<br/>';
		$out.='</a>';

		$out.="</div>";
		$out.='</p>';
		$out.="</td>\n";

		$this->itemCount++;
		return $out;
	}

	function outputEnd() {
		return '</tr></table>'."\n";
	}
}

function permissions_cmp($a, $b) {
	global $permissions_data;

	$aProtectionLevel = $permissions_data['permission'][$a]['protectionLevel'];
	$bProtectionLevel = $permissions_data['permission'][$b]['protectionLevel'];

	if($aProtectionLevel != $bProtectionLevel) {
		if(strlen($aProtectionLevel)==0) return 1;
		if(strlen($bProtectionLevel)==0) return -1;

		return strcmp($aProtectionLevel, $bProtectionLevel);
	}

	$aGroup = $permissions_data['permission'][$a]['permissionGroup'];
	$bGroup = $permissions_data['permission'][$b]['permissionGroup'];

	if($aGroup != $bGroup) {
		return strcmp($aGroup, $bGroup);
	}

	return strcmp($a, $b);
}

// Make a link to this page, with the current query vars attached and desired params added/modified
function makelink($query_vars, $params=array()) {
	$link=get_permalink();

	$p = array_merge($query_vars, $params);

	// Page 1 is the default, don't clutter urls with it...
	if($p['fdpage'] == 1)
		unset($p['fdpage']);
	// Likewise for list style...
	if($p['fdstyle'] == 'list')
		unset($p['fdstyle']);

	$vars=linkify($p);
	if(strlen($vars)==0)
		return $link;
	if(strpos($link,'?')===false)
		$link.='?';
	else
		$link.='&';
	return $link.$vars;
}

// Return the key value pairs in http-get-parameter format as a string
function linkify($vars) {
	$retvar = '';
	foreach($vars as $k => $v) {
		if($k!==null && $v!==null && $v!='')
			$retvar .= $k.'='.$v.'&';
	}
	return substr($retvar,0,-1);
}

function widget_fdroidlatest($args) {
	extract($args);
	echo $before_widget;
	echo $before_title . 'Latest Apps' . $after_title;
	
	$handle = fopen(getenv('DOCUMENT_ROOT').'/repo/latestapps.dat', 'r');
	if ($handle) {
		while (($buffer = fgets($handle, 4096)) !== false) {
			$app = explode("\t", $buffer);
			echo '<a href="/repository/browse/?fdid='.$app[0].'">';
			if(isset($app[2]) && trim($app[2])) {
				echo '<img src="' . site_url() . '/repo/icons/'.$app[2].'" style="width:32px;border:none;float:right;" />';
			}
			echo $app[1].'<br />';
			if(isset($app[3]) && trim($app[3])) {
				echo '<span style="color:#BBBBBB;">'.$app[3].'</span>';
			}
			echo '</a><br style="clear:both;" />';
		}
		fclose($handle);
	}
	
	echo $after_widget;
}

$wp_fdroid = new FDroid();


?>

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

class FDroid
{

	// Our text domain, for internationalisation
	var $textdom='wp-fdroid';

	// Constructor
	function FDroid() {
		// Add filters etc here!
		add_shortcode('fdroidrepo',array($this, 'do_shortcode'));
		add_filter('query_vars',array($this, 'queryvars'));
		$this->inited=false;
	}


	// Register additional query variables. (Handler for the 'query_vars' filter)
	function queryvars($qvars) {
		$qvars[]='fdfilter';
		$qvars[]='fdid';
		$qvars[]='fdpage';
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

	// Make a link to this page, with the given query parameter string added
	function makelink($params) {
		$link=get_permalink();
		if(strlen($params)==0)
			return $link;
		if(strpos($link,'?')===false)
			$link.='?';
		else
			$link.='&';
		$link.=$params;
		return $link;
	}

	// Handler for the 'fdroidrepo' shortcode.
	//  $attribs - shortcode attributes
	//  $content - optional content enclosed between the starting and ending shortcode
	// Returns the generated content.
	function do_shortcode($attribs,$content=null) {
		global $wp_query,$wp_rewrite;
		$this->lazyinit();

		$page=1;
		if(isset($wp_query->query_vars['fdpage'])) {
			$page=(int)$wp_query->query_vars['fdpage'];
			if($page==0)
				$page=1;
		}

		$filter=null;
		if(isset($wp_query->query_vars['fdfilter']))
			$filter=$wp_query->query_vars['fdfilter'];

		$out=$this->get_apps($page,$filter);
		return $out;

	}



	function get_apps($page,$filter=null) {

		if($filter===null)
			$out="<p>All applications";
		else
			$out="<p>Applications matching ".$filter;
		$out.="</p>";

		$perpage=10;
		$skipped=0;
		$got=0;
		$total=0;

		$xml = simplexml_load_file("/home/fdroid/public_html/repo/index.xml");
		foreach($xml->children() as $app) {

			foreach($app->children() as $el) {
				switch($el->getName()) {
					case "name":
						$name=$el;
						break;
				}
			}

			if($filter===null || stristr($name,$filter)) {
				if($skipped<($page-1)*$perpage) {
					$skipped++;
				} else if($got<$perpage) {
					$out.="<p>".$name."</p>";
					$got++;
				}
				$total++;
			}

		}

		$numpages=ceil((float)$total/$perpage);

		$out.='<p>';
		if($page==1) {
			$out.="&lt;&lt;first ";
			$out.="&lt;prev ";
		} else {
			$out.='<a href="'.$this->makelink("fdpage=1").'">&lt;&lt;first</a> ';
			$out.='<a href="'.$this->makelink("fdpage=".($page-1)).'">&lt;&lt;prev</a> ';
		}
		$out.=" Page $page of $numpages ";
		if($page==$numpages) {
			$out.="next&gt; ";
			$out.="last&gt;&gt; ";
		} else {
			$out.='<a href="'.$this->makelink("fdpage=".($page+1)).'">next&gt;</a> ';
			$out.='<a href="'.$this->makelink("fdpage=".$numpages).'">last&gt;&gt;</a> ';
		}
		$out.='</p>';

		return $out;
	}



}

$wp_fdroid = new FDroid();


?>

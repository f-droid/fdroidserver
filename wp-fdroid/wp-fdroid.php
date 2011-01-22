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

    var $site_path = "/home/fdroid/public_html";

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
    //  $content - optional content enclosed between the starting and
    //             ending shortcode
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

        $filter=$wp_query->query_vars['fdfilter'];
        $fdid=$wp_query->query_vars['fdid'];

        if($fdid!==null)
            $out=$this->get_app($fdid);
        else
            $out=$this->get_apps($page,$filter);
        return $out;

    }


    function get_app($id) {

        $xml = simplexml_load_file($this->site_path."/repo/index.xml");
        foreach($xml->children() as $app) {

            $attrs=$app->attributes();
            if($attrs['id']==$id) {
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
                        case "description":
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

                $out='<div id="appheader">';
                $out.='<div style="float:left;padding-right:10px;"><img src="http://f-droid.org/repo/icons/'.$icon.'" width=48></div>';
                $out.='<p><span style="font-size:20px">'.$name."</span>";
                $out.="<br>".$summary."</p>";
                $out.="</div>";

                $out.="<p>".$desc."</p>";

                $out.="<p><b>License:</b> ".$license."</p>";

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

                $out.="<h3>Packages</h3>";
                foreach($apks as $apk) {
                    $out.="<p><b>Version ".$apk['version']."</b> - ";
                    $out.='<a href="http://f-droid.org/repo/'.$apk['apkname'].'">download</a> ';
                    $out.=$apk['size']." bytes";
                    $out.="</p>";
                }

                $out.='<hr><p><a href="'.$this->makelink("").'">Index</a></p>';

                return $out;
            }
        }
        return "<p>Application not found</p>";
    }


    function get_apps($page,$filter=null) {

        if($filter===null)
            $out="<p>All applications";
        else
            $out="<p>Applications matching ".$filter;
        $out.="</p>";

        $perpage=30;
        $skipped=0;
        $got=0;
        $total=0;

        $xml = simplexml_load_file($this->site_path."/repo/index.xml");
        foreach($xml->children() as $app) {

            if($app->getName() == 'repo') continue;
            $attrs=$app->attributes();
            $id=$attrs['id'];
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
                    case "license":
                        $license=$el;
                        break;
                }
            }

            if($filter===null || stristr($name,$filter)) {
                if($skipped<($page-1)*$perpage) {
                    $skipped++;
                } else if($got<$perpage) {

                    $out.="<hr>\n";
                    $out.='<div id="appheader">';

                    $out.='<div style="float:left;padding-right:10px;"><img src="http://f-droid.org/repo/icons/'.$icon.'" style="width:48px;"></div>';

                    $out.='<div style="float:right;">';
                    $out.='<p><a href="';
                    $out.=$this->makelink("fdid=".$id);
                    $out.='">Details...</a>';
                    $out.="</p>";
                    $out.="</div>\n";

                    $out.='<p><span style="font-size:20px">'.$name."</span>";
                    $out.="<br>".$summary."</p>\n";

                    $out.="</div>\n";

                    $got++;
                }
                $total++;
            }

        }

        $numpages=ceil((float)$total/$perpage);

        $out.='<hr><p>';
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

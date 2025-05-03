### WAF Detection (waf-detect:nginxgeneric) found on 47.108.50.94:8002

----
**Details**: **waf-detect:nginxgeneric** matched at 47.108.50.94:8002

**Protocol**: HTTP

**Full URL**: http://47.108.50.94:8002/

**Timestamp**: Sat May 3 07:08:08 +0000 UTC 2025

**Template Information**

| Key | Value |
| --- | --- |
| Name | WAF Detection |
| Authors | dwisiswant0, lu4nx |
| Tags | waf, tech, misc |
| Severity | info |
| Description | A web application firewall was detected. |
| CWE-ID | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| CVSS-Score | 0.00 |

**Request**
```http
POST / HTTP/1.1
Host: 47.108.50.94:8002
User-Agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Connection: close
Content-Length: 27
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

_=<script>alert(1)</script>
```

**Response**
```http
HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Content-Type: text/html;charset=utf-8
Date: Sat, 03 May 2025 07:08:08 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
Set-Cookie: PHPSESSID=8l67md9cllnk91q5ih6fo2jes7; path=/
X-Powered-By: PHP/5.6.9

<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta charset="utf-8" />
    <title>Get the pikachu</title>

    <meta name="description" content="overview &amp; stats" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0" />

    <!-- bootstrap & fontawesome -->
    <link rel="stylesheet" href="assets/css/bootstrap.min.css" / >
    <link rel="stylesheet" href="assets/font-awesome/4.5.0/css/font-awesome.min.css" />

    <!-- page specific plugin styles -->

    <!-- text fonts -->
    <link rel="stylesheet" href="assets/css/fonts.googleapis.com.css" />

    <!-- ace styles -->
    <link rel="stylesheet" href="assets/css/ace.min.css" class="ace-main-stylesheet" id="main-ace-style" />

    <!--[if lte IE 9]>
    <link rel="stylesheet" href="assets/css/ace-part2.min.css" class="ace-main-stylesheet" />
    <![endif]-->
    <link rel="stylesheet" href="assets/css/ace-skins.min.css" />
    <link rel="stylesheet" href="assets/css/ace-rtl.min.css" />

    <!--[if lte IE 9]>
    <link rel="stylesheet" href="assets/css/ace-ie.min.css" />
    <![endif]-->

    <!-- inline styles related to this page -->

    <!-- ace settings handler -->
    <script src="assets/js/ace-extra.min.js"></script>

    <!-- HTML5shiv and Respond.js for IE8 to support HTML5 elements and media queries -->

    <!--[if lte IE 8]>
    <script src="assets/js/html5shiv.min.js"></script>
    <script src="assets/js/respond.min.js"></script>
    <![endif]-->
    <script src="assets/js/jquery-2.1.4.min.js"></script>
    <script src="assets/js/bootstrap.min.js"></script>

</head>

<body class="no-skin">
<div id="navbar" class="navbar navbar-default          ace-save-state">
    <div class="navbar-container ace-save-state" id="navbar-container">

        <div class="navbar-header pull-left">
            <a href="index.php" class="navbar-brand">
                <small>
                    <i class="fa fa-key"></i>
                    Pikachu 漏洞练习平台 pika~pika~
                </small>
            </a>
        </div>

        <div class="navbar-buttons navbar-header pull-right" role="navigation">
            <ul class="nav ace-nav">

                <li class="light-blue dropdown-modal">
                    <a data-toggle="dropdown" href="#" class="dropdown-toggle">
                        <img class="nav-user-photo" src="assets/images/avatars/pikachu1.png" alt="Jason's Photo" />
                        <span class="user-info">
									<small>欢迎</small>
									骚年
                        </span>
                    </a>

                </li>
            </ul>
        </div>
    </div><!-- /.navbar-container -->
</div>

<div class="main-container ace-save-state" id="main-container">
    <script type="text/javascript">
        try{ace.settings.loadState('main-container')}catch(e){}
    </script>


    <div id="sidebar" class="sidebar                  responsive                    ace-save-state">
        <script type="text/javascript">
            try{ace.settings.loadState('sidebar')}catch(e){}
        </script>

        <ul class="nav nav-list">
            <li class="active open">
                <a href="index.php">
                    <i class="ace-icon glyphicon glyphicon-tags"></i>
                    <span class="menu-text"> 系统介绍 </span>
                </a>

                <b class="arrow"></b>
            </li>

            <li class="">
                <a href="#" class="dropdown-toggle">
                    <i class="ace-icon glyphicon glyphicon-lock"></i>
                    <span class="menu-text">
								暴力破解
							</span>

                    <b class="arrow fa fa-angle-down"></b>
                </a>

                <b class="arrow"></b>

                <ul class="submenu">
                    <li class="" >
                        <a href="vul/burteforce/burteforce.php">
                            <i class="menu-icon fa fa-caret-right"></i>
                            概述
                        </a>

                        <b class="arrow"></b>
                    </li>
                    <li class="" >
                        <a href="vul/burteforce/bf_form.php">
                            <i class="menu-icon fa fa-caret-right"></i>
                            基于表单的暴力破解
                        </a>

                        <b class="arrow"></b>
                    </li>

                    <li class="">
                        <a href="vul/burteforce/bf_server.php">
                            <i class="menu-icon fa fa-caret-right"></i>
        .... Truncated ....
```

References: 
- https://github.com/Ekultek/WhatWaf

**CURL command**
```sh
curl -X 'POST' -d '_=<script>alert(1)</script>' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Host: 47.108.50.94:8002' -H 'User-Agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36' 'http://47.108.50.94:8002/'
```

----

Generated by [Nuclei v3.3.9](https://github.com/projectdiscovery/nuclei)
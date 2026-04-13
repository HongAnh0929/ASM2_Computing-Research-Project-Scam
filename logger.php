<?php

function log_block($title){
    log_line("================================");
    log_line("🚀 $title");
    log_line("================================");
}

function log_line($msg){
    $time = date("H:i:s");
    file_put_contents(
        __DIR__ . "/app.log",
        "[$time] I/APP: $msg\n",
        FILE_APPEND
    );
}

function log_success($msg){
    log_line("✅ $msg");
}

function log_warning($msg){
    log_line("⚠️ $msg");
}

function log_error($msg){
    log_line("❌ $msg");
}
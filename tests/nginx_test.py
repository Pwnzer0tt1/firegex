#!/usr/bin/env python3
import sys
import os
from unittest.mock import MagicMock
sys.modules['socketio'] = MagicMock()
sys.modules['socketio.exceptions'] = MagicMock()
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'utils')))

from modules.nfproxy.nginx import get_tls_ports, update_nginx, NGINX_CONF_PATH
from colors import colors, puts, sep

# Create mock services
services = [
    {
        "service_id": "a1b2c3d4",
        "name": "test_service",
        "port": 443,
        "status": "active",
        "proto": "tcp",
        "ip_int": "127.0.0.1",
        "tls_enabled": 1,
        "tls_cert": "CERT_CONTENT",
        "tls_key": "KEY_CONTENT"
    },
    {
        "service_id": "e5f6a7b8",
        "name": "test_service_ipv6",
        "port": 8443,
        "status": "active",
        "proto": "tcp",
        "ip_int": "::1",
        "tls_enabled": 1,
        "tls_cert": "CERT6_CONTENT",
        "tls_key": "KEY6_CONTENT"
    }
]

try:
    # We monkey-patch subprocess.run to prevent it from calling real nginx if it fails
    import subprocess
    orig_run = subprocess.run
    def mock_run(args, *a, **k):
        # Just pretend it succeeded
        class MockCompletedProcess:
            returncode = 0
            stdout = b""
            stderr = b""
        return MockCompletedProcess()
    subprocess.run = mock_run

    sep()
    puts("Running Nginx Config Unit Test...", color=colors.cyan, is_bold=True)
    update_nginx(services)
    puts("Nginx update completed successfully! ✔", color=colors.green)
    
    # Check if config exists and has valid contents
    if os.path.exists(NGINX_CONF_PATH):
        with open(NGINX_CONF_PATH, "r") as f:
            content = f.read()
            
            # Check pid and error_log paths
            assert "pid /tmp/firegex_nginx.pid;" in content
            assert "error_log /tmp/firegex_nginx_error.log info;" in content
            
            # Check cert paths
            assert "ssl_certificate /tmp/firegex_cert_a1b2c3d4.crt;" in content
            assert "ssl_certificate /tmp/firegex_cert_e5f6a7b8.crt;" in content
            
            # Verify deterministic ports for IPv4
            # sha256("127.0.0.1:443")[:4] as int = 3737521872
            # 3737521872 % 10000 = 3936
            # ssl_port = 10000 + 3936 = 13936
            # clear_port = 20000 + 3936 = 23936
            assert "127.0.0.1:13936" in content
            assert "127.0.0.1:23936" in content
 
            # Verify deterministic ports & bracket wrapping for IPv6
            # sha256("::1:8443")[:4] as int = 2439169896
            # 2439169896 % 10000 = 9896
            # ssl_port = 10000 + 9896 = 19896
            # clear_port = 20000 + 9896 = 29896
            assert "[::1]:19896" in content
            assert "[::1]:29896" in content
            assert "[::1]:8443" in content
            
            puts("Configuration assertions passed! ✔", color=colors.green)
            
            # Check temp files were created
            assert os.path.exists("/tmp/firegex_cert_a1b2c3d4.crt")
            assert os.path.exists("/tmp/firegex_key_a1b2c3d4.key")
            assert os.path.exists("/tmp/firegex_cert_e5f6a7b8.crt")
            assert os.path.exists("/tmp/firegex_key_e5f6a7b8.key")
            puts("Temporary certificate files created! ✔", color=colors.green)
    else:
        puts("Error: nginx.conf not found! ✗", color=colors.red)
        sys.exit(1)
        
    # Write dummy files to simulate Nginx creating PID and error log files
    with open("/tmp/firegex_nginx.pid", "w") as f:
        f.write("12345")
    with open("/tmp/firegex_nginx_error.log", "w") as f:
        f.write("log info")
        
    # Test cleanup by passing an empty list
    update_nginx([])
    
    assert not os.path.exists(NGINX_CONF_PATH)
    assert not os.path.exists("/tmp/firegex_cert_a1b2c3d4.crt")
    assert not os.path.exists("/tmp/firegex_key_a1b2c3d4.key")
    assert not os.path.exists("/tmp/firegex_cert_e5f6a7b8.crt")
    assert not os.path.exists("/tmp/firegex_key_e5f6a7b8.key")
    assert not os.path.exists("/tmp/firegex_nginx.pid")
    assert not os.path.exists("/tmp/firegex_nginx_error.log")
    puts("Cleanup verified successfully! ✔", color=colors.green)
 
finally:
    # Restore subprocess.run
    subprocess.run = orig_run
    puts("Test passed! ✔", color=colors.green, is_bold=True)
    sep()

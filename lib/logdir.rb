class Logdir
	class << self
		def logfiles
			%w[ /var/log/messages
    			/var/log/authlog
    			/var/log/secure
    			/var/log/xferlog
    			/var/log/maillog
    			/var/log/syslog
    			/var/log/auth.log
    			/var/log/user.log
    			/var/log/apache2/access_log
    			/var/log/apache2/error_log
    			/var/log/httpd/access_log
    			/var/log/httpd/error_log
    			/var/log/nginx/access.log
    			/var/log/nginx/error.log
    		]
    	end
    end
end
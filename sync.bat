"C:\Program Files (x86)\WinSCP\winscp.exe" /console /command "option batch continue" "option confirm off" "open sftp://foo:123@192.168.1.200:22" "option transfer binary" "put T:\CPP\CertMngr /home/foo/certmngr" "pause" 
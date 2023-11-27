# hook2cmd
A WebHook server to catch webhook from GitHub, GitLab, and POST; written in Go

to build the you probably need to

go get gopkg.in/yaml.v3

git pull it !

install it as a service

`
Copy to /etc/systemd/system or /usr/lib/systemd/system
cd /home/debian/hook2cmd
cp hook2cmd.service /etc/systemd/system/.
adjust values : 'User' 'ExecStart' 'ExecStop' as needed
reload systemd services files 
systemctl daemon-reload
enable service
systemctl enable hook2cmd.service
systemctl is-enabled hook2cmd.service
systemctl start hook2cmd.service
journalctl -u hook2cmd.service
`
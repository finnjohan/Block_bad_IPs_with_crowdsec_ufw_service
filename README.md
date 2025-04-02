# Block_bad_IPs_with_crowdsec_ufw_service
Install the service to block bad actors with ufw and crowdsec
apt install python3-watchdog
nano /etc/systemd/system/log-monitor.service

[Unit]
Description=Apache Log Monitor for Suspicious Activity
After=network.target apache2.service
Requires=apache2.service

[Service]
Type=simple
#pattern_block_service.py blocks IPs while pattern_service.py just emails
#ExecStart=/usr/bin/python3 /usr/local/ki_bin/DDOS/pattern_service.py
ExecStart=/usr/bin/python3 /usr/local/ki_bin/DDOS/pattern_block_service.py
Restart=always
RestartSec=10
User=root
Group=root
WorkingDirectory=/usr/local/bin
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reload
sudo systemctl enable log-monitor.service
sudo systemctl start log-monitor.service
sudo systemctl status log-monitor.service

In the service modify the search path to where you have the script pattern_block_service.py
In the script modify email adress, excluded IPs/ranges and so on to your needs.


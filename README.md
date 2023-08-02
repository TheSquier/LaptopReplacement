# LaptopReplacement
Laptop replacement scripts for a corporate environment


###################################################################################

Author: Alexander Squier | xandersquier@outlook.com
Time to complete script: ~7 min 30s(6 minutes unattended. 1min 30s attended.)
Time to complete lite: ~2 minutes

Required Permissions: Standard User
#############################        USES       ###################################

This script helps aid in the successful setup, and testing of all needed functions
of the standard laptop. 


This script also functions as a guide or training aid for those who are just
stepping into the role of an EOL Technician as it offers what is essentially a
checklist of what to do during this process.


###########################     DESCRIPTION      ##################################

This is an application for backing up and restoring laptops to expidite the setup
process for replacements and first time configuration.  

###########################     PROCESS    #######################################

The Backup
1. User prefences are backed up for Avaya and browsers and outlook

2. Outlook registry values are backed up for easy restore

The Restore 
1. The clock ID is automatically collected.

2. All microsoft apps are closed

3. A Group Policy update is ran. This fixes many issues related to Drives and
other things controlled by Group Policy. 

4. Drivers with frequent issues are disabled. (IPv6 and Intel Smart Sound Tech.)

5. Outlook is started

7. Adobe Acrobat is set to default PDF reader

8. The user prefences in are restored (Avaya, Browsers, Outlook)

9. The script automatically enables bookmarks and favorites bar on Edge and Chrome

10.Testing is preformed on DNS and internet connectivity

11. Finally the technician is told to restart the computer and press enter to exit
the script.

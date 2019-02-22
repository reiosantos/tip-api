 
 <span style="font-family: TimesNewRoman; font-size:12px">


# TIP Installation Guide
---
### This document provides a step bystep guide on how to install and run the TIP sytstem

* Ensure you have **python 3.6** installed oin the system. else you follow
  [this guide](https://www.tecmint.com/install-python-in-linux/) on how to install it.

* Install **pip** on your system. Follow the instaructions on
  [this site](https://www.tecmint.com/install-pip-in-linux/) for more information. else :-

* Fedora/RHEL/CentOS

```bash
sudo dnf in python3-pip
```

* SUSE/OpenSuse

```bash
sudo zypper in python3-pip
```

* Debian/Uuntu

```bash
sudo apt-get install python3-pip
```
Copy if you have not done so already, the system folder form the installation media 
onto your system/OS. Place it under a directory you can access.

Assuming its placed under the ==**www**== folder of your system.

If ==**tip-system**== is the name of the system folder, then do:

```bash
cd tip-system
```

* install the system requirements.

```bash
pip install -r requirements.txt
```

Assuming all is well.

* The system can be run(*the default configurations, host localhost, port 5000*) with:-

```bash
python3 app.py
```

The system can now be accessed from the browser window.

```http
http://localhost/tip-system/web
```


 </span>
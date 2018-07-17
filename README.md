## News Log Analysis System

### Overview

> The Item Catalog project consists of developing an application that provides a list of items within a variety of categories, as well as provide a user registration and authentication system.

### Prerequisites
* [VirtualBox](https://www.virtualbox.org/)
* [Vagrant](https://www.vagrantup.com/)
* [Python3](https://www.python.org/)

  `$ pip3 install psycopg2`

### Install the Project

* Install VirtualBox and Vagrant
* Clone or Download the configuration file from [FSND-VM](https://github.com/udacity/fullstack-nanodegree-vm) repository
* Launch the Vagrant VM ( `vagrant up` )
* go to `/vagrant/catalog` within the VM
* Install the requirements with `sudo pip3 install -r requirements.txt`
* Run the application with `python3 application.py`
* Open your browser on [http://localhost:8000](http://localhost:8000)

### Launching the VM
* Install the vagrant VM after change directory to the directory you have cloned from FSND-VM repo

  `$ vagrant up `
* After installing vagrant virtual machine successfully , you need to log into it
  `$ vagrant ssh `
* Change directory to `$ cd /vagrant ` , this is the directory shared between the vagrant VM and your host machine

### Probable issue

> If you face any issue with running the project on this port ,
please stop the process working on this port and try to run again

You can use `fuser -k 8000/tcp` to kill process working on port 8000

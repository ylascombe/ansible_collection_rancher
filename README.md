 # Ansible Collection - ylascombe.rancher

Ansible collection to manage rancher projects.

Contains:
- a `rancher_project` module that enable to manage (create, update, delete) rancher projects.

# How to use `rancher_project` module

## Import the collection in your project

Classic method: 
`ansible-galaxy install ylascombe/rancher`

Development method:
Create a symbolic link from the `plugins/modules` folder of this project to `library` folder on your project 

## Use the module in a tasks:

```yaml
- hosts: localhost
  tasks:
    - name: Create a project with user password
      rancher_project:
        url: "https://<your rancher host>"
        rancher_user: <your user>
        rancher_password: "<your user password>"
        force_basic_auth: True
        validate_certs: False
        name: "<to create project name>"
        cluster_id: "<kubernetes cluster ID from rancher point of view>"
        state: present
    - name: Create a project with token
      rancher_project:
        url: "https://<your rancher host>"
        rancher_api_key: "<you api token>"
        force_basic_auth: True
        validate_certs: False
        name: "<to create project name>"
        cluster_id: "<kubernetes cluster ID from rancher point of view>"
        state: present
```

# Ansible Collection - ylascombe.rancher

Ansible collection that enable to manage rancher project via its API.

Contains:
- a `rancher_project` module that enable to manage (create, update, delete) rancher projects.
- **soon** a `rancher_token` module that enable to authenticate on rancher and get a Bearer token (already done in `rancher_project` module but will be extracted into this module)

# How to use it

## Import this collection into your project

Classic method:
`ansible-galaxy collection install ylascombe.rancher`

Dev method: 
`ln -s <path to this repo>/modules/plugins/rancher_project.py <path to your repo>/library/rancher_project.py``

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

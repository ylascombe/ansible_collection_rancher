Simple ansible module that enable to manage (create, update, delete) rancher projects.

# How to use it

* Import `library` folder into your project.
* Use the module in a tasks:

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

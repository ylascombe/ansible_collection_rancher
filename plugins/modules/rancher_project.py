#!/usr/bin/python
# -*- coding: utf-8 -*-
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
---
module: rancher_project
author:
  - Yohan LASCOMBE (@ylascombe)
version_added: "2.10"
short_description: Manage Rancher Project
description:
  - Create/update/delete Rancher Project through API.
options:
  url:
    description:
      - The Rancher URL.
    required: true
    type: str
  name:
    description:
      - The name of the Rancher Project.
    required: true
    type: str
  url_username:
    description:
      - The Rancher user for API authentication.
    default: admin
    type: str
    aliases: [ rancher_user ]
  url_password:
    description:
      - The Rancher password for API authentication.
    default: admin
    type: str
    aliases: [ rancher_password ]
  rancher_api_key:
    description:
      - The Rancher API key.
      - If set, C(url_username) and C(url_password) will be ignored.
    type: str
  cluster_id:
    description:
      - Cluster ID of kubernetes cluster from rancher point of view
    type: str
  namespaces:
    description:
      - List of project namespaces.
      - The list can be enforced with C(enable_namespace_removal) parameter.
    type: list
  enable_monitoring:
    description:
      - Is the prometheus/grafana stack should be deployed for this project
    type: bool
    default: no
  resource_quota:
    description:
      - Project global quotas.
      - Sum of each namespace quotas included in project must be lower or equal project quota.
    type: dict
    default: {}
  namespace_default_resource_quota:
    description:
      - Quota to apply by default to each namespace created on this project if no specific quota given
    type: dict
    default: {}
  state:
    description:
      - Delete the namespaces not found in the C(namespaces) parameters from the
      - list of namespaces found on the Project.
    default: present
    type: str
    choices: ["present", "absent"]
  enable_namespace_removal:
    description:
      - Delete the namespaces not found in the C(namespaces) parameters from the
      - list of namespaces found on the Project.
    default: True
    type: bool
  use_proxy:
    description:
      - If C(no), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    type: bool
    default: yes
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client authentication.
      - This file can also include the key as well, and if the key is included, I(client_key) is not required
    type: path
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL client authentication.
      - If I(client_cert) contains both the certificate and key, this option is not required.
    type: path
'''

EXAMPLES = '''
---
- name: Create a project and authenticate with given token.
  rancher_project:
      url: "https://rancher.example.com"
      rancher_api_key: "{{ some_api_token_value }}"
      name: "rancher_working_group"
      state: present
      cluster_id: "c-cluster-id"
      
- name: Authenticate and create a project.
  rancher_project:
      url: "https://rancher.example.com"
      rancher_user: "admin"
      rancher_password: "{{ some_api_token_value }}"
      name: "rancher_working_group"
      state: present
      cluster_id: "c-cluster-id"
      
- name: Update project to add quotas.
  rancher_project:
      url: "https://rancher.example.com"
      rancher_user: "admin"
      rancher_password: "{{ some_api_token_value }}"
      name: "rancher_working_group"
      state: present
      cluster_id: "c-cluster-id"
      resource_quota:
        limit:
          limitsCpu: "4000m"
          limitsMemory: "4096Mi"
      namespace_default_resource_quota:
        limit:
          limitsCpu: "1000m"
          limitsMemory: "1024Mi"

- name: Delete a project.
  rancher_project:
      url: "https://rancher.example.com"
      rancher_api_key: "{{ some_api_token_value }}"
      name: "rancher_working_group"
      cluster_id: "c-cluster-id"
      state: absent
'''

RETURN = '''
---
TODO
project:
    description: Information about the Project
    returned: On success
    type: complex
    contains:
        avatarUrl:
            description: The url of the Project avatar on Rancher server
            returned: always
            type: string
            sample:
                - "/avatar/a7440323a684ea47406313a33156e5e9"
        email:
            description: The Project email address
            returned: always
            type: string
            sample:
                - "foo.bar@example.com"
        id:
            description: The Project email address
            returned: always
            type: integer
            sample:
                - 42
        name:
            description: The name of the project.
            returned: always
            type: string
            sample:
                - "rancher_working_group"
        namespaces:
            description: The list of Project namespaces
            returned: always
            type: list
            sample:
                - ["john.doe@exemple.com"]
        orgId:
            description: The organization id that the project is part of.
            returned: always
            type: integer
            sample:
                - 1
'''

import json
import string
import requests
#import pdb

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec, basic_auth_header

__metaclass__ = type


class RancherProject(object):

    def __init__(self, module):
        self._module = module

        self.headers = {"Content-Type": "application/json"}
        self.cookies = {}
        rancher_url = module.params.get("url")
        if module.params.get('rancher_api_key', None):
            self.headers["Authorization"] = "Bearer %s" % module.params['rancher_api_key']
        else:
            token = self.get_rancher_token(rancher_url, module.params['url_username'],module.params['url_password'], module)
            self.headers["Authorization"] = str('Bearer %s' % token)
            
        self.headers["Accept"] = "*/*"
        self.headers["Cache-Control"] = "no-cache"
        self.headers["Host"] = rancher_url.replace('https://', '').replace('/','')
        #self.headers["Accept-Encoding"] = "gzip, deflate"
        self.headers["Connection"] = "keep-alive"
        self.headers["cache-control"] = "no-cache"

        self.rancher_url = rancher_url

    def _send_request(self, url, data=None, headers=None, method="GET", desc=''):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        if not headers:
            headers = []

        full_url = "{rancher_url}{path}".format(rancher_url=self.rancher_url, path=url)
        
        if method == 'GET':
            resp = requests.get(full_url, headers=headers, data=data)
        elif method == 'POST':
            resp = requests.post(full_url, headers=headers, data=data)
        elif method == 'PUT':
            resp = requests.put(full_url, headers=headers, data=data)
        elif method == 'DELETE':
            resp = requests.delete(full_url, headers=headers, data=data)
        else:
            self._module.fail_json(failed=True, msg="Method not expected %s" % (method))

        status_code = resp.status_code

        if status_code == 404:
            self._module.fail_json(failed=True, msg="Rancher Project API answered with HTTP %d and content %s (action detail: %s) (url: %s)" % (status_code, resp.text, desc, full_url))
            return None
        elif status_code == 401:
            self._module.fail_json(failed=True, msg="Unauthorized to perform action '%s' on '%s' header: %s. data: %s" % (method, full_url, self.headers, data))
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 409:
            self._module.fail_json(failed=True, msg="Project name is taken")
        elif status_code == 200:
            return self._module.from_json(resp.text)
        elif status_code == 201:
            return self._module.from_json(resp.text)

        self._module.fail_json(failed=True, msg="Rancher Project API answered with HTTP %d and content %s (action detail: %s) (url: %s)" % (status_code, resp.text, desc, full_url))


    def get_rancher_token(self, rancher_url, rancher_login, rancher_password, module):

        ui_session = dict()
        ui_session["ui-session"] = True

        data = dict(
            username=rancher_login,
            password=rancher_password,
            description="Fake UI Session from ansible module",
            responseType="json",
            ttl=1800000,
            labels=ui_session
        )

        headers = {"Content-Type": "application/json"}
        full_url = "{rancher_url}/v3-public/localProviders/local?action=login".format(rancher_url=rancher_url)

        stdout = "url: %s" % full_url
        stdout += "%s\ndata:%s" % (stdout, data)
        
        #resp, info = fetch_url(self._module, full_url, data=module.jsonify(data), headers=headers, method="POST")
        resp = requests.post("%s" % (full_url), data=json.dumps(data),headers=headers)

        # data = info # json.loads(info)
        #status_code = info["status"]
        status_code = resp.status_code
        content = resp.text

        if status_code == 404:
            return None
        elif status_code == 201:
            json_content = json.loads(content)
            token = json_content["token"]
            return token
        else:
            self._module.fail_json(failed=True, msg="get rancher token request end with %d status code with message: %s" % (status_code, content))
        return None


    def create_project(self, name, cluster_id, resource_quotas=dict(), namespace_default_resource_quota=dict()):
        url = "/v3/project?_replace=true"

        project = dict(
            enableProjectMonitoring="false",
            type='project',
            name=name,
            clusterId=cluster_id,
            resourceQuota=resource_quotas,
            namespaceDefaultResourceQuota=namespace_default_resource_quota,
        )

        self.headers["Content-Type"] = "application/json"

        response = self._send_request(url, data=project, headers=self.headers, method="POST",  desc="create project request")
        return response

    def get_project(self, name, cluster_id):
        url = "/v3/projects/?name={project_name}&clusterId={cluster_id}".format(project_name=name, cluster_id=cluster_id)

        response = self._send_request(url, headers=self.headers, method="GET", desc="get request")

        projects = response['data']

        if len(projects) == 0:
            return None

        return projects[0]

    #def update_project(self, name, cluster_id, resource_quotas=dict(), namespace_default_resource_quota=dict()):
    def update_project(self, name, cluster_id, project):
        url = "/v3/projects/{project_id}?_replace=true".format(project_id=project["id"])
        
        ## pdb.set_trace()
        response = self._send_request(url, data=project, headers=self.headers, method="PUT")
        #self._module.fail_json(failed=True, msg="get rancher token request end with %d status code with message: %d %s" % (response, response.text))
        return response
    
    def delete_project(self, project_id):
        url = "/v3/projects/{project_id}".format(project_id=project_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response

def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[['url_username', 'url_password']],
        mutually_exclusive=[['url_username', 'rancher_api_key']],
    )
    return module


argument_spec = url_argument_spec()
# remove unnecessary arguments
del argument_spec['force']
# del argument_spec['force_basic_auth']
del argument_spec['http_agent']

argument_spec.update(
    state=dict(choices=['present', 'absent'], default='present'),
    name=dict(type='str', required=True),
    cluster_id=dict(type='str', required=True),
    namespaces=dict(type='list', required=False),
    url=dict(type='str', required=True),
    rancher_api_key=dict(type='str', no_log=True),
    enable_namespace_removal=dict(type='bool', default=True),
    url_username=dict(aliases=['rancher_user'], default='admin'),
    url_password=dict(aliases=['rancher_password'], default='admin', no_log=True),
    # force_basic_auth=dict(aliases=['force_basic_auth'], type='bool', default=True),
    enable_monitoring=dict(type='bool', default=False),
    resource_quota=dict(type='dict', default={}),
    namespace_default_resource_quota=dict(type='dict', default={}),
)

def main():

    module = setup_module_object()
    state = module.params['state']
    name = module.params['name']
    cluster_id = module.params['cluster_id']
    namespaces = module.params['namespaces']
    enable_namespace_removal = module.params['enable_namespace_removal']
    enable_monitoring = module.params['enable_monitoring']
    resource_quota = module.params['resource_quota']
    namespace_default_resource_quota = module.params['namespace_default_resource_quota']

    rancher_iface = RancherProject(module)

    changed = False
    if state == 'present':

        project = rancher_iface.get_project(name, cluster_id)

        if project is None:
            project = rancher_iface.create_project(name, cluster_id)
            # project = rancher_iface.get_project(name)
            changed = True
        else:
            copy = project
            copy['enableProjectMonitoring'] = enable_monitoring
            copy['resourceQuota'] = resource_quota
            copy['namespaceDefaultResourceQuota'] = namespace_default_resource_quota
            
            #if enable_monitoring != project['enableProjectMonitoring']:
            
            project = rancher_iface.update_project(name, cluster_id, copy)
            changed = True
        # if namespaces is not None:
        #     cur_namespaces = rancher_iface.get_project_namespaces(project.get("id"))
        #     plan = diff_namespaces(namespaces, cur_namespaces)
        #     for member in plan.get("to_add"):
        #         rancher_iface.add_project_member(project.get("id"), member)
        #         changed = True
        #     if enable_namespace_removal:
        #         for member in plan.get("to_del"):
        #             rancher_iface.delete_project_member(project.get("id"), member)
        #             changed = True
        # project['namespaces'] = rancher_iface.get_project_namespaces(project.get("id"))

        res_project = dict()
        res_project['id'] = project['id']
        res_project['name'] = project['name']
        res_project['cluster_id'] = project['clusterId']
        res_project['created'] = project['created']
        res_project['creator_id'] = project['creatorId']
        if 'description' in project.keys():
          res_project['description'] = project['description']
        res_project['labels'] = project['labels']
        res_project['resource_quota'] = project['resourceQuota']
        res_project['monitoring_enabled'] = project['enableProjectMonitoring']

        module.exit_json(failed=False, changed=changed, project=project)
    elif state == 'absent':
        project = rancher_iface.get_project(name, cluster_id)
        if project is None:
            module.exit_json(failed=False, changed=False, message="No project found")
        result = rancher_iface.delete_project(project['id'])
        module.exit_json(failed=False, changed=True, message=result.get("message"))


def diff_namespaces(target, current):
    diff = {"to_del": [], "to_add": []}
    for member in target:
        if member not in current:
            diff["to_add"].append(member)
    for member in current:
        if member not in target:
            diff["to_del"].append(member)
    return diff


if __name__ == '__main__':
    main()

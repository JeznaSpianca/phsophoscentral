#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from sophoscentral_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SophosCentralConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SophosCentralConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            self.save_progress("Json uspel")
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            self.save_progress("Sem pred json response")
            return self._process_json_response(r, action_result)

        if 'text' in r.headers.get('Content-Type', ''):
            self.save_progress("Sem pred text response")
            return RetVal(phantom.APP_SUCCESS, r.text)
        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", params=None, headers=None):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url, headers=headers, params=params
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _make_rest_call_new(self, endpoint, action_result, method="get", params=None, headers=None, data=None, json=None):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._centralURL + endpoint

        try:
            r = request_func(
                url, headers=headers, params=params, data=data, json=json
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.
        headers = {"x-api-key": self._api_key, "Authorization": "Basic " + self._auth_key}
        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('', action_result, params=None, headers=headers)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        self.save_progress(response)
        return action_result.set_status(phantom.APP_SUCCESS, "BLAA")

    def _get_token(self, param, action_result):
        """
        This function gets the jwt token needed to make API calls to Sophos REST API.
        """
        url = "https://id.sophos.com/api/v2/oauth2/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"grant_type": "client_credentials", "client_id": self._clientID, "client_secret": self._clientSecret, "scope": "token"}
        self.save_progress(self._clientID)
        self.save_progress(self._clientSecret)
        try:
            r = requests.post(url, headers=headers, data=data)
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), r.__dict__
            )
        a = r.json()
        self.save_progress(json.dumps(a))
        self.save_progress("BLA")
        data = r.json()
        return data["access_token"]

    def _handle_list_endpoints(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        params = {}
        if len(param) != 1:
            for key, value in param.items():
                if key == 'context':
                    continue
                params[key] = value
        else:
            params = None

        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            '/endpoint/v1/endpoints', action_result, headers=headers, params=params
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_describe_alert(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        path = "/common/v1/alerts/" + param['alert_id']
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            path, action_result, method="get", headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_user(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)
        ep = "/common/v1/directory/users/" + param["user_id"]
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            ep, action_result, method="delete", headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_item(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        payload = {"type": param['type'], "properties": {"sha256": param["sha256"]}, "comment": param["comment"]}
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            '/endpoint/v1/settings/blocked-items', action_result, method="post", headers=headers, json=payload
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_blocked_items(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/endpoint/v1/settings/blocked-items"
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/common/v1/directory/users"
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_user_groups(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/common/v1/directory/user-groups"
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_blocked_item(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/endpoint/v1/settings/blocked-items/" + param['item_id']
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, method="delete", headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_request_scan(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/endpoint/v1/endpoints/" + param['endpoint_id'] + '/scans'
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, method="post", headers=headers, json={}
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_allow_item(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/endpoint/v1/settings/allowed-items"
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # Preparing query data
        prop = {
            "fileName": param["fileName"],
            "path": param["path"],
            "sha256": param["sha256"]
        }
        payload = {}
        payload["comment"] = param["comment"]
        payload["type"] = param["type"]
        if "originEndpointId" in param:
            payload["originEndpointId"] = param["originEndpointId"]
        if "originPersonId" in param:
            payload["originPersonId"] = param["originPersonId"]
        payload["properties"] = prop
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, method="post", headers=headers, json=payload
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_action_alert(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/common/v1/alerts/" + param['alert_id'] + '/actions'
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        payload = {"action": param['action'], "message": param['message']}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, method="post", headers=headers, json=payload
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_allowed_items(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/endpoint/v1/settings/allowed-items"
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tamper_protection_settings(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        query = "/endpoint/v1/endpoints/" + param["endpointID"] + "/tamper-protection"
        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            query, action_result, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_getalerts_new(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get API token
        token = self._get_token(param, action_result)

        headers = {"X-Tenant-ID": self._tenantID, "Authorization": "Bearer " + token}
        # make rest call
        ret_val, response = self._make_rest_call_new(
            '/common/v1/alerts', action_result, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_getalerts(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        headers = {"x-api-key": self._api_key, "Authorization": "Basic " + self._auth_key}

        # make rest call
        ret_val, response = self._make_rest_call(
            '/siem/v1/alerts', action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_getevents_date(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        headers = {"x-api-key": self._api_key, "Authorization": "Basic " + self._auth_key}
        params = {'from_date': int(param['date'])}
        # make rest call
        ret_val, response = self._make_rest_call(
            '/siem/v1/events', action_result, params=params, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_getevents(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        headers = {"x-api-key": self._api_key, "Authorization": "Basic " + self._auth_key}
        self.save_progress(json.dumps(param))
        params = {}
        if len(param) != 1:
            for key, dt in param.items():
                # When a playbook sends parameters, there is a parameter called context,
                # and it doesn't include relevant data, that should be passed in the API call
                if key == 'context':
                    continue
                params[key] = dt
        else:
            params = None
        self.save_progress(json.dumps(params))
        # make rest call
        ret_val, response = self._make_rest_call(
            '/siem/v1/events', action_result, params=params, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_data'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'getevents':
            ret_val = self._handle_getevents(param)

        elif action_id == 'getalerts':
            ret_val = self._handle_getalerts(param)

        elif action_id == 'getevents_date':
            ret_val = self._handle_getevents_date(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'getalerts_new':
            ret_val = self._handle_getalerts_new(param)

        elif action_id == 'tamper_protection_settings':
            ret_val = self._handle_tamper_protection_settings(param)

        elif action_id == 'get_allowed_items':
            ret_val = self._handle_get_allowed_items(param)

        elif action_id == 'get_blocked_items':
            ret_val = self._handle_get_blocked_items(param)

        elif action_id == 'block_item':
            ret_val = self._handle_block_item(param)

        elif action_id == 'describe_alert':
            ret_val = self._handle_describe_alert(param)

        elif action_id == 'run_action_alert':
            ret_val = self._handle_run_action_alert(param)

        elif action_id == 'list_user_groups':
            ret_val = self._handle_list_user_groups(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        elif action_id == 'request_scan':
            ret_val = self._handle_request_scan(param)

        elif action_id == 'delete_blocked_item':
            ret_val = self._handle_delete_blocked_item(param)

        elif action_id == 'allow_item':
            ret_val = self._handle_allow_item(param)

        elif action_id == 'delete_user':
            ret_val = self._handle_delete_user(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('baseURL')
        self._api_key = config.get('api_key')
        self._auth_key = config.get('auth_key')
        self._clientID = config.get('clientID')
        self._clientSecret = config.get('clientSecret')
        self._tenantID = config.get('tenantID')
        self._centralURL = config.get('centralURL')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SophosCentralConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SophosCentralConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
